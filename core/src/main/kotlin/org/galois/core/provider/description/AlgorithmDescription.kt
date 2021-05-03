package org.galois.core.provider.description

class AlgorithmDescription(val name: String, val family: String) {
    lateinit var keySizes: IntArray
    var parameters: MutableList<Parameter>? = null

    override fun toString() = """Algorithm: $name
        |Family: $family
        |Key sizes: ${keySizes.joinToString()}
        |${printParameters()}
        """.trimMargin()

    private fun printParameters() = parameters?.let { list ->
        "Parameters:\n ${list.joinToString("\n") { it.toString() }}\n"
    } ?: ""

    class Parameter(
        val field: String,
        val description: String,
        val conditionType: ParameterDescription.ConditionType,
        val condition: String,
        val decryptionRequired: Boolean
    ) {
        override fun toString() =
            " - $field: $description. Condition: ${formatCondition()}. ${if (decryptionRequired) "Required for decryption" else ""}"

        private fun formatCondition() = when (conditionType) {
            ParameterDescription.ConditionType.REGEX -> "-> Pattern: $condition"
            ParameterDescription.ConditionType.RANGE -> "-> In range $condition"
            ParameterDescription.ConditionType.LOWER_LIMIT -> "-> >= $condition"
            ParameterDescription.ConditionType.DISTINCT_VALUES -> "-> Possible values: $condition"
            ParameterDescription.ConditionType.BOOLEAN -> "-> true or false"
            else -> ParameterDescription.ConditionType.NONE
        }
    }
}