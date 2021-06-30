package org.galois.core.benchmark

import kotlinx.coroutines.*
import org.galois.core.engine.EncryptionDetail
import org.galois.core.engine.EngineConfiguration
import org.galois.core.engine.EngineMode
import org.galois.core.engine.GaloisEngine
import org.galois.core.provider.fpe.dff.DFF_ALGORITHM_NAME
import org.galois.core.provider.fpe.ff3.FF3_ALGORITHM_NAME
import org.galois.core.provider.ope.acope.ACOPE_ALGORITHM_NAME
import org.galois.core.provider.ope.aicd.AICD_ALGORITHM_NAME
import org.galois.core.provider.ope.fope.FOPE_ALGORITHM_NAME
import org.galois.core.provider.ope.pore.PORE_ALGORITHM_NAME
import org.galois.core.provider.ppe.cryptopan.CRYPTOPAN_ALGORITHM_NAME
import org.galois.core.provider.ppe.hpcbc.HPCBC_ALGORITHM_NAME
import org.openjdk.jmh.annotations.*
import org.openjdk.jmh.profile.GCProfiler
import org.openjdk.jmh.profile.LinuxPerfNormProfiler
import org.openjdk.jmh.profile.LinuxPerfProfiler
import org.openjdk.jmh.results.format.ResultFormatType
import org.openjdk.jmh.runner.Runner
import org.openjdk.jmh.runner.options.OptionsBuilder
import tech.tablesaw.api.Table
import java.awt.Desktop
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileWriter
import java.net.URI
import java.time.Duration
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

enum class BenchmarkConfig(val algorithm: String, val column: String) {
    FOPE_AGE(FOPE_ALGORITHM_NAME, "age"),
    FOPE_SALARY(FOPE_ALGORITHM_NAME, "salary"),
    PORE_AGE(PORE_ALGORITHM_NAME, "age"),
    PORE_SALARY(PORE_ALGORITHM_NAME, "salary"),
    AICD_AGE(AICD_ALGORITHM_NAME, "age"),
    AICD_SALARY(AICD_ALGORITHM_NAME, "salary"),
    CRYPTOPAN_IP(CRYPTOPAN_ALGORITHM_NAME, "ip-address"),
    CRYPTOPAN_ZIP(CRYPTOPAN_ALGORITHM_NAME, "zip-code"),
    HPCBC_IP(HPCBC_ALGORITHM_NAME, "ip-address"),
    HPCBC_ZIP(HPCBC_ALGORITHM_NAME, "zip-code"),
    DFF_CCN(DFF_ALGORITHM_NAME, "credit-card-number"),
    DFF_CF(DFF_ALGORITHM_NAME, "cf"),
    FF3_CCN(FF3_ALGORITHM_NAME, "credit-card-number"),
    FF3_CF(FF3_ALGORITHM_NAME, "cf")
}

private fun createEngineConfig(params: BenchmarkConfig): EngineConfiguration {
    val encryptionDetails = listOf(EncryptionDetail(params.column, params.algorithm))
    val encryptConfig =
        EngineConfiguration("benchmark", EngineMode.ENCRYPT, encryptionDetails)

    if (params.column == "cf") encryptionDetails[0].params.cipherSpecific["radix"] = 36
    if (params.column == "ip-address") encryptionDetails[0].params.cipherSpecific["ip"] = "4"
    if (params == BenchmarkConfig.HPCBC_ZIP) encryptionDetails[0].params.cipherSpecific["block_size"] = 3

    return encryptConfig
}

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
class EncryptionTimeAndSizeBenchmark {

    @Param(
        "FOPE_AGE",
        "FOPE_SALARY",
        "PORE_AGE",
        "PORE_SALARY",
        "AICD_AGE",
        "AICD_SALARY",
        "CRYPTOPAN_IP",
        "CRYPTOPAN_ZIP",
        "HPCBC_IP",
        "HPCBC_ZIP",
        "DFF_CCN",
        "DFF_CF",
        "FF3_CCN",
        "FF3_CF"
    )
    private lateinit var params: BenchmarkConfig

    @Param("100", "1000", "10000")
    private var rows = 0

    private lateinit var dataset: Table
    private lateinit var encryptConfig: EngineConfiguration

    private lateinit var engine: GaloisEngine
    private lateinit var encrypted: Table

    private var initialSize: Int = 0
    private lateinit var deltas: MutableList<Int>

    private val sizeFile = File("benchmarks/sizes.log")

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
class DecryptionTimeBenchmark {

    @Param(
        "FOPE_AGE",
        "FOPE_SALARY",
        "PORE_AGE",
        "PORE_SALARY",
        "AICD_AGE",
        "AICD_SALARY",
        "CRYPTOPAN_IP",
        "CRYPTOPAN_ZIP",
        "HPCBC_IP",
        "HPCBC_ZIP",
        "DFF_CCN",
        "DFF_CF",
        "FF3_CCN",
        "FF3_CF"
    )
    private lateinit var params: BenchmarkConfig

    @Param("100", "1000", "10000")
    private var rows = 0

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

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
class BaselineBenchmark {
    @Benchmark
    fun baseline() {
    }
}

fun main() {
    val start = LocalDateTime.now()
    println("===== ${start.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING STARTED =====")
    // run the command "sudo sysctl -w kernel.perf_event_paranoid=0" for perf
    val opt = OptionsBuilder()
        .include(BaselineBenchmark::class.java.simpleName)
        .include(EncryptionTimeAndSizeBenchmark::class.java.simpleName)
        .include(DecryptionTimeBenchmark::class.java.simpleName)
        .shouldDoGC(true)
        .shouldFailOnError(true)
        .forks(1)
        .resultFormat(ResultFormatType.CSV)
        .result("benchmarks/benchmark_result.csv")
        .output("benchmarks/benchmark_output.log")
        .mode(Mode.AverageTime)
        .addProfiler(GCProfiler::class.java)
        .addProfiler(LinuxPerfProfiler::class.java)
        .addProfiler(LinuxPerfNormProfiler::class.java)
        .build()

    Runner(opt).run()
    val stop = LocalDateTime.now()
    println("===== ${stop.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING FINISHED =====")
    println("===== ELAPSED TIME: ${Duration.between(start, stop).toMinutes()} minutes =====")

    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
        Desktop.getDesktop().browse(URI("https://www.youtube.com/watch?v=CSvFpBOe8eY"))
    }
}