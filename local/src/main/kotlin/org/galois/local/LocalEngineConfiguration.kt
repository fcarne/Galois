package org.galois.local

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.galois.core.engine.*
import java.io.File

class LocalEngineConfiguration(
    var input: String,
    val outputDir: String,
    outputFilename: String,
    mode: Mode,
    encryptionDetails: List<EncryptionDetail>
) : EngineConfiguration(outputFilename, mode, encryptionDetails)

class LocalTaxonomyTree(val outputFilename: String, tree: TaxonomyNode): TaxonomyTree(tree)

class LocalTaxonomyTreeDeserializer : JsonDeserializer<LocalTaxonomyTree>() {
    override fun deserialize(p: JsonParser?, ctxt: DeserializationContext?): LocalTaxonomyTree? {
        val node = p?.codec?.readTree<JsonNode>(p) ?: return null

        val outputFileName: String = node.get("output_filename").asText()
        val taxonomyTreePath = node.get("tree").asText()

        val mapper = jacksonObjectMapper().setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)

        return LocalTaxonomyTree(outputFileName, mapper.readValue(File(taxonomyTreePath)))
    }
}

class LocalTaxonomyTreeSerializer(private val outputDir: String) : JsonSerializer<LocalTaxonomyTree>() {
    override fun serialize(value: LocalTaxonomyTree?, gen: JsonGenerator, serializers: SerializerProvider?) {
        if (value == null) return

        gen.writeStartObject()
        gen.writeStringField("output_filename", value.outputFilename)
        gen.writeStringField("tree", File(outputDir, value.outputFilename).absolutePath)
        gen.writeEndObject()
    }
}