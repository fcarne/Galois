package org.galois.local

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.coroutines.runBlocking
import org.galois.core.engine.GaloisEngine
import org.galois.core.engine.EngineMode
import org.galois.core.engine.TaxonomyTree
import org.galois.core.provider.GaloisJCE
import picocli.CommandLine
import tech.tablesaw.api.Table
import java.io.File
import java.io.IOException
import java.lang.Exception
import java.security.InvalidKeyException
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

    @CommandLine.Command(name = "do-final", description = ["Runs the Galois Engine using the given config file"])
    fun doFinal(
        @CommandLine.Parameters(
            paramLabel = "config",
            description = ["The path of the json configuration file"]
        ) configFile: File
    ): Int {
        val mapper = jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        SimpleModule().addDeserializer(TaxonomyTree::class.java, LocalTaxonomyTreeDeserializer())
            .also { mapper.registerModule(it) }

        val config = try {
            mapper.readValue<LocalEngineConfiguration>(configFile)
        } catch (e: JsonParseException) {
            System.err.println("Something is wrong with the configuration file, please check it again")
            return 10
        } catch (e: IOException) {
            System.err.println("Please check that the configuration file exists and is readable")
            return 10
        }

        val datasetFile = File(config.input)

        val dataset = try {
            Table.read().csv(datasetFile)
        } catch (e: IOException) {
            System.err.println(
                "There was a problem while reading from ${datasetFile.absolutePath}, " +
                        "please check that it is valid and tha the file is readable"
            )
            return 10
        }

        val engine = GaloisEngine(dataset, config)
        val computedDataset: Table

        println("Started ${if (config.mode == EngineMode.ENCRYPT) "encrypting" else "decrypting"}")


        val time = try {
            measureTimeMillis { runBlocking { computedDataset = engine.compute() } }
        } catch (e: IllegalArgumentException) {
            System.err.println(e.localizedMessage)
            return 10
        } catch (e: InvalidKeyException) {
            System.err.println(e.localizedMessage)
            return 10
        } catch (e: Exception) {
            System.err.println(e.localizedMessage)
            return 20
        }

        println("${if (config.mode == EngineMode.ENCRYPT) "Encrypted" else "Decrypted"} ${dataset.rowCount()} lines in $time ms")
        println("Saving files to directory ${config.outputDir}...")

        val computedDatasetFile = File(config.outputDir, config.outputFilename)

        try {
            computedDataset.write().csv(computedDatasetFile)
        } catch (e: IOException) {
            System.err.println("There was a problem while saving the computed dataset to ${config.outputDir} ")
        }

        val configOutput = engine.tidyConfiguration()
        configOutput.encryptionDetails.forEach {
            it.params.taxonomyTree?.let { taxonomyTree ->
                taxonomyTree as LocalTaxonomyTree
                val taxonomyOutputFile = File(config.outputDir, taxonomyTree.outputFilename)
                mapper.writeValue(taxonomyOutputFile, taxonomyTree.root)
            }
        }

        configOutput as LocalEngineConfiguration
        configOutput.input = computedDatasetFile.absolutePath

        SimpleModule().addSerializer(
            LocalTaxonomyTree::class.java, LocalTaxonomyTreeSerializer(configOutput.outputDir)
        ).also { mapper.registerModule(it) }

        val configOutputFile = File(config.outputDir, configFile.name)
        mapper.writeValue(configOutputFile, configOutput)

        return 0
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
            System.err.println(e.message)
            10
        }
    }
}

fun main(args: Array<String>) {
    val exitCode = CommandLine(GaloisTerminal()).execute(*args)
    println("Process finished with exit code $exitCode")
}
