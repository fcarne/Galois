package org.galois.local

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.coroutines.runBlocking
import org.galois.core.engine.GaloisEngine
import org.galois.core.engine.Mode
import org.galois.core.engine.TaxonomyTree
import org.galois.core.provider.GaloisJCE
import picocli.CommandLine
import tech.tablesaw.api.Table
import java.io.File
import kotlin.system.measureTimeMillis

@CommandLine.Command(
    name = "GaloisTerminal", subcommands = [CommandLine.HelpCommand::class],
    exitCodeListHeading = "Exit Codes:%n",
    exitCodeList = [
        " 0:Successful program execution",
        " 2:Help invoked",
        "10:Usage error: user input for the command was incorrect, e.g., the wrong number of arguments, a bad flag, a bad syntax in a parameter, etc.",
        "20:Internal software error: an exception occurred when invoking the business logic of this command."]
)
class GaloisTerminal {

    @CommandLine.Command(
        name = "do-final",
        description = ["Runs the Galois Engine using the given config file"]
    )
    fun doFinal(
        @CommandLine.Parameters(
            paramLabel = "config",
            description = ["The path of the json configuration file"]
        ) configFile: File
    ) = runBlocking {
        val mapper = jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        SimpleModule().addDeserializer(TaxonomyTree::class.java, LocalTaxonomyTreeDeserializer())
            .also { mapper.registerModule(it) }

        val config = mapper.readValue<LocalEngineConfiguration>(configFile)
        val datasetFile = File(config.input)
        require(datasetFile.isFile && datasetFile.exists() && datasetFile.canRead())
        { "The input file must exists and be readable" }

        require(File(config.outputDir).mkdir() || File(config.outputDir).isDirectory) { "The output directory is not a directory" }

        val dataset = Table.read().csv(datasetFile)

        val engine = GaloisEngine(dataset, config)
        val computedDataset: Table

        println("Started ${if (config.mode == Mode.ENCRYPT) "encrypting" else "decrypting"}")

        val time = measureTimeMillis { computedDataset = engine.compute() }

        println("${if (config.mode == Mode.ENCRYPT) "Encrypted" else "Decrypted"} ${dataset.rowCount()} lines in $time ms")
        println("Saving files to directory ${config.outputDir}...")

        val computedDatasetFile = File(config.outputDir, config.outputFilename)
        computedDataset.write().csv(computedDatasetFile)

        val configOutput = engine.tidyConfiguration()
        configOutput.encryptionDetails.forEach {
            it.params.taxonomyTree?.let { taxonomyTree ->
                taxonomyTree as LocalTaxonomyTree
                val taxonomyOutputFile = File(config.outputDir, taxonomyTree.outputFilename)
                mapper.writeValue(taxonomyOutputFile, taxonomyTree.tree)
            }
        }

        configOutput as LocalEngineConfiguration
        configOutput.input = computedDatasetFile.absolutePath

        SimpleModule().addSerializer(LocalTaxonomyTree::class.java, LocalTaxonomyTreeSerializer(configOutput.outputDir))
            .also { mapper.registerModule(it) }

        val configOutputFile = File(config.outputDir, configFile.name)
        mapper.writeValue(configOutputFile, configOutput)
    }

    @CommandLine.Command(name = "desc", description = ["Displays the description of the algorithms parameters"])
    fun getDescription(
        @CommandLine.Parameters(
            arity = "0..*", paramLabel = "algorithms",
            description = ["The names of the algorithms for which display the parameters description"]
        ) algorithms: Array<String>?
    ): Int {
        return try {
            if (algorithms == null) println(GaloisJCE.getDescription().joinToString("\n"))
            else algorithms.forEach { println(GaloisJCE.getDescription(it)) }
            0
        } catch (e: IllegalArgumentException) {
            println(e.message)
            64
        }


    }
}

fun main(args: Array<String>) {
    val exitCode = CommandLine(GaloisTerminal()).execute(*args)
    println("Exit code: $exitCode")
}
