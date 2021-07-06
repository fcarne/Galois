package org.galois.core.benchmark

import kotlinx.coroutines.runBlocking
import org.galois.core.engine.EncryptionDetail
import org.galois.core.engine.EngineConfiguration
import org.galois.core.engine.EngineMode
import org.galois.core.engine.GaloisEngine
import org.galois.core.provider.ope.fope.FOPE_ALGORITHM_NAME
import org.galois.core.provider.ope.pore.PORE_ALGORITHM_NAME
import org.galois.core.provider.ppe.hpcbc.HPCBC_ALGORITHM_NAME
import org.openjdk.jmh.annotations.*
import org.openjdk.jmh.results.format.ResultFormatType
import org.openjdk.jmh.runner.Runner
import org.openjdk.jmh.runner.options.OptionsBuilder
import tech.tablesaw.api.Table
import java.awt.Desktop
import java.awt.Toolkit
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileWriter
import java.net.URI
import java.time.Duration
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

enum class MultipleParamsConfig(val algorithm: String, val column: String, val param: Any) {
    FOPE_8(FOPE_ALGORITHM_NAME, "age", 8),
    FOPE_32(FOPE_ALGORITHM_NAME, "age", 32),
    FOPE_64(FOPE_ALGORITHM_NAME, "age", 64),
    PORE_3(PORE_ALGORITHM_NAME, "age", 3),
    PORE_512(PORE_ALGORITHM_NAME, "age", 512),
    PORE_4096(PORE_ALGORITHM_NAME, "age", 4096),
    HPCBC_1(HPCBC_ALGORITHM_NAME, "ipv6", 1),
    HPCBC_2(HPCBC_ALGORITHM_NAME, "ipv6", 2),
    HPCBC_6(HPCBC_ALGORITHM_NAME, "ipv6", 6),
    HPCBC_8(HPCBC_ALGORITHM_NAME, "ipv6", 8)
}

private fun createEngineConfig(params: MultipleParamsConfig): EngineConfiguration {
    val encryptionDetails = listOf(EncryptionDetail(params.column, params.algorithm))
    val encryptConfig =
        EngineConfiguration("benchmark", EngineMode.ENCRYPT, encryptionDetails)

    when (params.algorithm) {
        FOPE_ALGORITHM_NAME -> encryptionDetails[0].params.cipherSpecific["tau"] = params.param
        PORE_ALGORITHM_NAME -> encryptionDetails[0].params.cipherSpecific["q"] = params.param
        HPCBC_ALGORITHM_NAME -> {
            encryptionDetails[0].params.cipherSpecific["block_size"] = params.param
            encryptionDetails[0].params.cipherSpecific["ip"] = "6"
        }
    }

    return encryptConfig
}

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
class MultipleParamsEncryptionTimeAndSizeBenchmark {

    @Param(
        "FOPE_8",
        "FOPE_32",
        "FOPE_64",
        "PORE_3",
        "PORE_512",
        "PORE_4096",
        "HPCBC_1",
        "HPCBC_2",
        "HPCBC_6",
        "HPCBC_8"
    )
    private lateinit var params: MultipleParamsConfig

    private var rows = 1000

    private lateinit var dataset: Table
    private lateinit var encryptConfig: EngineConfiguration

    private lateinit var engine: GaloisEngine
    private lateinit var encrypted: Table

    private var initialSize: Int = 0
    private lateinit var deltas: MutableList<Int>

    private val sizeFile = File("benchmarks/multiple/sizes.log")

    @Setup(Level.Trial)
    fun loadDataset() {
        val datasetStream = this.javaClass.getResourceAsStream("/benchmark_sample.csv")
        dataset = Table.read().csv(datasetStream).retainColumns(params.column).inRange(rows)

        encryptConfig = createEngineConfig(params)

        val baos = ByteArrayOutputStream()
        dataset.write().csv(baos)
        initialSize = baos.size()
        deltas = ArrayList()
    }

    @Setup(Level.Invocation)
    fun initEngine() {
        // forces a new key
        engine = GaloisEngine(dataset, encryptConfig)
    }

    @Benchmark
    fun encrypt() = runBlocking { encrypted = engine.compute() }

    @TearDown(Level.Invocation)
    fun getDelta() {
        val baos = ByteArrayOutputStream()
        encrypted.write().csv(baos)
        deltas.add(baos.size() - initialSize)
    }

    @TearDown(Level.Trial)
    fun getMeanDelta() {
        deltas.sort()
        val meanDelta = deltas.average()
        val result = """$params - $rows. Initial size: $initialSize Bytes. 
            |Increment: ${String.format("%.3f", meanDelta)} Bytes (${
            String.format(
                "%.3f",
                meanDelta / initialSize * 100
            )
        }%)
            |Min: ${deltas[0]}. Max: ${deltas[deltas.lastIndex]}
            |""".trimMargin()

        println(result)
        val fileWriter = FileWriter(sizeFile, true)
        fileWriter.write(result)
        fileWriter.close()

        deltas.clear()
    }
}

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
class MultipleParamsDecryptionTimeBenchmark {

    @Param(
        "FOPE_8",
        "FOPE_32",
        "FOPE_64",
        "PORE_3",
        "PORE_512",
        "PORE_4096",
        "HPCBC_1",
        "HPCBC_2",
        "HPCBC_6",
        "HPCBC_8"
    )
    private lateinit var params: MultipleParamsConfig

    private var rows = 1000

    private lateinit var dataset: Table
    private lateinit var encryptConfig: EngineConfiguration
    private lateinit var engine: GaloisEngine

    @Setup(Level.Trial)
    fun loadDataset() {
        val datasetStream = this.javaClass.getResourceAsStream("/benchmark_sample.csv")
        dataset = Table.read().csv(datasetStream).retainColumns(params.column).inRange(rows)

        encryptConfig = createEngineConfig(params)
    }

    @Setup(Level.Invocation)
    fun initEngine() {
        // forces a new key
        val encryptionEngine = GaloisEngine(dataset, encryptConfig)
        val encryptedDataset = runBlocking { encryptionEngine.compute() }
        engine = GaloisEngine(encryptedDataset, encryptionEngine.tidyConfiguration())
    }

    @Benchmark
    fun decrypt() = runBlocking { engine.compute() }
}

fun main() {
    val start = LocalDateTime.now()
    println("===== ${start.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING STARTED =====")
    val opt = OptionsBuilder()
        .include(BaselineBenchmark::class.java.simpleName)
        .include(MultipleParamsEncryptionTimeAndSizeBenchmark::class.java.simpleName)
        .include(MultipleParamsDecryptionTimeBenchmark::class.java.simpleName)
        .shouldDoGC(true)
        .shouldFailOnError(true)
        .forks(1)
        .resultFormat(ResultFormatType.CSV)
        .result("benchmarks/multiple/benchmark_result.csv")
        .output("benchmarks/multiple/benchmark_output.log")
        .mode(Mode.AverageTime)
        .build()

    Runner(opt).run()
    val stop = LocalDateTime.now()
    println("===== ${stop.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING FINISHED =====")
    println("===== ELAPSED TIME: ${Duration.between(start, stop).toMinutes()} minutes =====")
}