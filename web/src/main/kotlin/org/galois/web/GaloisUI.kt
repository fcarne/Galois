package org.galois.web

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import io.ktor.application.*
import io.ktor.features.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.jackson.*
import io.ktor.request.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.*
import org.galois.core.engine.EngineConfiguration
import org.galois.core.engine.GaloisEngine
import org.galois.core.provider.GaloisJCE
import org.slf4j.event.Level
import tech.tablesaw.api.Table
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.InvalidKeyException
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream


fun main() {
    embeddedServer(Netty, port = 8080, host = "127.0.0.1") {
        install(ContentNegotiation) {
            jackson {
                enable(SerializationFeature.INDENT_OUTPUT)
                setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
                propertyNamingStrategy = PropertyNamingStrategies.SNAKE_CASE
            }
        }

        install(CallLogging) { level = Level.INFO }

        routing {
            resource("/", "static/index.html")

            get("/details") { call.respond(GaloisJCE.getDescription()) }

            post("/doFinal") {
                val multipartData = call.receiveMultipart().readAllParts()

                val mapper = jacksonObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                    .enable(SerializationFeature.INDENT_OUTPUT)
                    .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)

                val configuration = try {
                    multipartData.first { it.name == "config" }.let {
                        it as PartData.FormItem
                        mapper.readValue<EngineConfiguration>(it.value)
                    }
                } catch (e: JsonParseException) {
                    System.err.println(e.message)
                    call.response.status(HttpStatusCode.UnprocessableEntity)
                    call.respondText { "Something is wrong with the configuration file, please check it again" }
                    return@post
                }

                val dataset = try {
                    multipartData.first { it.name == "dataset" }.let {
                        it as PartData.FileItem
                        val fileBytes = it.streamProvider()
                        Table.read().csv(fileBytes, "Dataset")
                    }
                } catch (e: IOException) {
                    System.err.println(e.message)
                    call.response.status(HttpStatusCode.UnprocessableEntity)
                    call.respondText { "Something is wrong with the dataset, please check it again" }
                    return@post
                }

                try {
                    val engine = GaloisEngine(dataset, configuration)
                    val result = engine.compute()

                    call.respondBytes(
                        createZip(engine.tidyConfiguration(), result, mapper),
                        ContentType.Application.Zip,
                        HttpStatusCode.OK
                    )
                } catch (e: IllegalArgumentException) {
                    System.err.println(e.message)
                    call.response.status(HttpStatusCode.UnprocessableEntity)
                    call.respondText { e.localizedMessage }
                } catch (e: InvalidKeyException) {
                    System.err.println(e.message)
                    call.response.status(HttpStatusCode.UnprocessableEntity)
                    call.respondText { e.localizedMessage }
                } catch (e: Exception) {
                    System.err.println(e.message)
                    call.response.status(HttpStatusCode.InternalServerError)
                    call.respondText { e.localizedMessage }
                }
            }

            static("assets") { resources("static/assets") }
        }

    }.start(wait = true)
}

fun createZip(configuration: EngineConfiguration, result: Table, mapper: ObjectMapper): ByteArray = runBlocking {
    withContext(Dispatchers.IO) {
        val baos = ByteArrayOutputStream()
        val zos = ZipOutputStream(baos)

        val configZip = ZipEntry("config.json")
        zos.putNextEntry(configZip)
        zos.write(mapper.writeValueAsBytes(configuration))
        zos.closeEntry()

        val datasetZip = ZipEntry(configuration.outputFilename)
        val datasetBaos = ByteArrayOutputStream()
        zos.putNextEntry(datasetZip)

        result.write().csv(datasetBaos)
        zos.write(datasetBaos.toByteArray())
        zos.closeEntry()

        zos.finish()

        baos.close()

        baos.toByteArray()
    }
}