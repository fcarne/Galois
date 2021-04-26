package org.galois.core.provider.description

class AlgorithmDescription(val name: String) {
    lateinit var keySizes: IntArray
    var parameters: MutableList<Parameter>? = null

    override fun toString() = """Algorithm: $name
        |Key sizes: ${keySizes.joinToString()}
        |${printParameters()}
        """.trimMargin()

    private fun printParameters() = parameters?.let { list ->
        "Parameters:\n ${list.joinToString("\n") { it.toString() }}\n"
    } ?: ""

    class Parameter(
        private val field: String,
        private val description: String,
        val conditionType: ParameterDescription.ConditionType,
        private val condition: String
    ) {
        override fun toString() = " - $field: $description. Condition: ${formatCondition()}"

        private fun formatCondition() = when (conditionType) {
            ParameterDescription.ConditionType.REGEX -> "-> Pattern: $condition"
            ParameterDescription.ConditionType.RANGE -> "-> In range $condition"
            ParameterDescription.ConditionType.LOWER_LIMIT -> "-> >$condition"
            ParameterDescription.ConditionType.DISTINCT_VALUES -> "-> Possible values: $condition"
            ParameterDescription.ConditionType.BOOLEAN -> "-> true or false"
            else -> ParameterDescription.ConditionType.NONE
        }
    }
}