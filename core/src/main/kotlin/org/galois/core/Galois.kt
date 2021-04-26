package org.galois.core

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.coroutines.runBlocking
import org.galois.core.engine.EngineConfiguration
import org.galois.core.engine.GaloisEngine
import org.galois.core.engine.Mode
import org.galois.core.provider.GaloisJCE
import tech.tablesaw.api.Table
import java.io.File
import java.net.URLDecoder
import java.nio.charset.Charset

fun main() {
    val mapper = jacksonObjectMapper().enable(SerializationFeature.INDENT_OUTPUT)
        .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
        .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

    val tablePath = URLDecoder.decode(object {}.javaClass.getResource("/sample.csv")!!.file, Charset.defaultCharset())
    val table = Table.read().csv(tablePath)

    val configFile = File(object {}.javaClass.getResource("/engine_test.json")!!.toURI())
    val encryptConfig = mapper.readValue<EngineConfiguration>(configFile)
    val encryptedEngine = GaloisEngine(table, encryptConfig)
    val encrypted = runBlocking { encryptedEngine.compute() }

    println(encrypted.first(10))

    val decryptConfig = encryptedEngine.tidyConfiguration()
    decryptConfig.mode = Mode.DECRYPT
    val decryptEngine = GaloisEngine(encrypted, decryptConfig)
    val decrypted = runBlocking { decryptEngine.compute() }

    println("DECRYPTED:" + decrypted.first(10))
    println("ORIGINAL:" + table.first(10))

    GaloisJCE.getDescription().forEach { println(it) }
}