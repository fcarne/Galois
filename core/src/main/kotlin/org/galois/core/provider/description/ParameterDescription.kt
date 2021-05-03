package org.galois.core.provider.description

annotation class ParameterDescription(
    val description: String,
    val conditionType: ConditionType,
    val condition: String = "",
    val decryptionRequired: Boolean = false
) {
    enum class ConditionType {
        REGEX, RANGE, LOWER_LIMIT, DISTINCT_VALUES, BOOLEAN, NONE
    }
}

