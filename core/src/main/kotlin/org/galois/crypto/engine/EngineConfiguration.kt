package org.galois.crypto.engine

import com.fasterxml.jackson.annotation.*

enum class Mode {
    @JsonProperty("encrypt")
    ENCRYPT,

    @JsonProperty("decrypt")
    DECRYPT
}

open class EngineConfiguration(
    val outputFilename: String,
    var mode: Mode = Mode.ENCRYPT,
    val encryptionDetails: List<EncryptionDetail>
) : Cloneable {
    public override fun clone() = EngineConfiguration(outputFilename, mode, encryptionDetails.map { it.copy() })
}

data class EncryptionDetail(
    val columnName: String,
    val cipher: String,
    var key: String? = null,
    @JsonInclude(
        value = JsonInclude.Include.CUSTOM,
        valueFilter = ParamsFilter::class
    ) val params: EncryptionParams = EncryptionParams()
) {
    companion object {
        class ParamsFilter {
            override fun equals(other: Any?) = if (other == null) true else EncryptionParams() == other
            override fun hashCode() = javaClass.hashCode()
        }
    }
}

data class EncryptionParams(
    val keySize: Int? = null,
    val taxonomyTree: TaxonomyTree? = null,
    @get:[JsonIgnore JsonAnyGetter] @JsonAnySetter var cipherSpecific: MutableMap<String, Any> = HashMap()
)

data class TaxonomyTree(val outputFilename: String, var tree: TaxonomyNode)

data class TaxonomyNode(
    var cat: String,
    @JsonFormat(with = [JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY])
    val subcats: MutableList<TaxonomyNode>?
)