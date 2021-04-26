package org.galois.crypto.provider.description

annotation class ParameterDescription(
    val description: String,
    val conditionType: ConditionType,
    val condition: String = ""
) {
    enum class ConditionType {
        REGEX, RANGE, LOWER_LIMIT, DISTINCT_VALUES, BOOLEAN, NONE
    }
}

