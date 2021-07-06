package org.galois.core.benchmark

import kotlinx.coroutines.runBlocking
import org.galois.core.engine.EncryptionDetail
import org.galois.core.engine.EngineConfiguration
import org.galois.core.engine.EngineMode
import org.galois.core.engine.GaloisEngine
import org.openjdk.jmh.annotations.*
import org.openjdk.jmh.profile.GCProfiler
import org.openjdk.jmh.results.format.ResultFormatType
import org.openjdk.jmh.runner.Runner
import org.openjdk.jmh.runner.options.OptionsBuilder
import tech.tablesaw.api.Table
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileWriter
import java.time.Duration
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit

private fun createEngineConfig(params: BenchmarkConfig): EngineConfiguration {
    val encryptionDetails = listOf(EncryptionDetail(params.column, params.algorithm))
    return EngineConfiguration("benchmark", EngineMode.ENCRYPT, encryptionDetails)
}

@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 5, timeUnit = TimeUnit.SECONDS)
@State(Scope.Benchmark)
class EncryptionTimeAndSizePOREBenchmark {

    @Param("PORE_AGE", "PORE_SALARY")
    private lateinit var params: BenchmarkConfig

    @Param("100", "1000", "10000")
    private var rows = 0

    private lateinit var dataset: Table
    private lateinit var encryptConfig: EngineConfiguration

    private lateinit var engine: GaloisEngine
    private lateinit var encrypted: Table

    private var initialSize: Int = 0
    private lateinit var deltas: MutableList<Int>

    private val sizeFile = File("benchmarks/pore/sizes.log")

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
class DecryptionTimePOREBenchmark {

    @Param("PORE_AGE", "PORE_SALARY")
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

fun main() {
    val start = LocalDateTime.now()
    println("===== ${start.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING STARTED =====")
    // run the command "sudo sysctl -w kernel.perf_event_paranoid=0" for perf
    val opt = OptionsBuilder()
        .include(BaselineBenchmark::class.java.simpleName)
        .include(EncryptionTimeAndSizePOREBenchmark::class.java.simpleName)
        .include(DecryptionTimePOREBenchmark::class.java.simpleName)
        .shouldDoGC(true)
        .shouldFailOnError(true)
        .forks(1)
        .resultFormat(ResultFormatType.CSV)
        .result("benchmarks/pore/benchmark_result.csv")
        .output("benchmarks/pore/benchmark_output.log")
        .mode(Mode.AverageTime)
        .addProfiler(GCProfiler::class.java)
        .build()

    Runner(opt).run()
    val stop = LocalDateTime.now()
    println("===== ${stop.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))} BENCHMARKING FINISHED =====")
    println("===== ELAPSED TIME: ${Duration.between(start, stop).toMinutes()} minutes =====")

/*    val datasetStream = object {}.javaClass.getResourceAsStream("/benchmark_sample.csv")
    val dataset = Table.read().csv(datasetStream).retainColumns("age").inRange(100)
    println(dataset.printAll())
    val baos = ByteArrayOutputStream()
    dataset.write().csv(baos)
    println(baos.size())

    val encryptConfig = createEngineConfig(BenchmarkConfig.PORE_AGE)
    val engine = GaloisEngine(dataset, encryptConfig)
    runBlocking {
        val encrypted = engine.compute()
        println(encrypted.printAll())
        val baosE = ByteArrayOutputStream()
        encrypted.write().csv(baosE)
        println(baosE.size())
        println(baosE.size() - baos.size())
        println((baosE.size() - baos.size()) / baos.size().toDouble())
        PORESecretKey(Base64.getDecoder().decode(engine.tidyConfiguration().encryptionDetails[0].key)).apply {
            println(n)
            println(q)
        }
    }*/
}