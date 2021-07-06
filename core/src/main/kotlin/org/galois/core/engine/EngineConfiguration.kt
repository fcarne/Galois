package org.galois.core.engine

import com.fasterxml.jackson.annotation.*

enum class EngineMode {
    @JsonProperty("encrypt")
    ENCRYPT,

    @JsonProperty("decrypt")
    DECRYPT
}

open class EngineConfiguration(
    val outputFilename: String,
    var mode: EngineMode = EngineMode.ENCRYPT,
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

    fun copy(): EncryptionDetail = EncryptionDetail(columnName, cipher, key, params.copy())

}

data class EncryptionParams(
    var keySize: Int? = null,
    val taxonomyTree: TaxonomyTree? = null,
    @get:[JsonIgnore JsonAnyGetter] @JsonAnySetter var cipherSpecific: MutableMap<String, Any> = HashMap()
) {
    fun copy(): EncryptionParams = EncryptionParams(
        keySize,
        taxonomyTree?.let { TaxonomyTree(it.root.copy()) },
        HashMap(cipherSpecific)
    )
}

open class TaxonomyTree(@JsonProperty("tree") var root: TaxonomyNode)

data class TaxonomyNode(
    var cat: Any,
    @JsonFormat(with = [JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY])
    val subcats: MutableList<TaxonomyNode>?
) {
    fun toList(): List<Any> = listOf(cat) + (subcats?.flatMap { it.toList() } ?: emptyList())
}