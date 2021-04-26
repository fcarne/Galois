package org.galois

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.galois.crypto.engine.GaloisEngine
import org.galois.crypto.engine.Mode
import crypto.provider.GaloisJCE
import kotlinx.coroutines.runBlocking
import picocli.CommandLine
import tech.tablesaw.api.Table
import java.io.File
import kotlin.system.exitProcess
import kotlin.system.measureTimeMillis

@CommandLine.Command(name = "GaloisTerminal", subcommands = [CommandLine.HelpCommand::class])
class GaloisTerminal {
    @CommandLine.Command(name = "do-final", description = ["Runs the Galois Engine using the given config file"])
    fun doFinal(
        @CommandLine.Parameters(
            paramLabel = "config",
            description = ["The path of the json configuration file"]
        ) configFile: File
    ) = runBlocking {
        val mapper = jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        val config = mapper.readValue<LocalEngineConfiguration>(configFile)
        val dataset = Table.read().csv(config.input)

        val engine = GaloisEngine(dataset, config)
        val computedDataset: Table
        val time = measureTimeMillis { computedDataset = engine.compute() }
        println("${if (config.mode == Mode.ENCRYPT) "Encrypted" else "Decrypted"} ${dataset.rowCount()} lines in $time ms")
        println("Saving files to directory ${config.outputDir}")

        val computedDatasetFile = File(config.outputDir, config.outputFilename)
        computedDataset.write().csv(computedDatasetFile)

        config.encryptionDetails.forEach {
            it.params.taxonomyTree?.let { taxonomyTree ->
                val taxonomyOutputFile = File(config.outputDir, taxonomyTree.outputFilename)
                mapper.writeValue(taxonomyOutputFile, taxonomyTree.tree)
            }
        }

        val configOutputFile = File(config.outputDir, "config.json")
        mapper.writeValue(configOutputFile, engine.tidyConfiguration())
    }

    @CommandLine.Command(name = "desc", description = ["Displays the description of the algorithms parameters"])
    fun getDescription(
        @CommandLine.Parameters(
            arity = "0..*", paramLabel = "algorithms",
            description = ["The names of the algorithms for which display the parameters description"]
        ) algorithms: Array<String>?
    ) {
        if (algorithms == null) println(GaloisJCE.getDescription().joinToString("\n"))
        else algorithms.forEach { println(GaloisJCE.getDescription(it)) }
    }
}

fun main(args: Array<String>) {
    val exitCode = CommandLine(GaloisTerminal()).execute(*args)
    exitProcess(exitCode)
}
