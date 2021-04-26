package org.galois.core.provider.ppe.cryptopan

import org.galois.core.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class CryptoPAnParameterSpec(maxLength: Int = 16) : AlgorithmParameterSpec {
    @ParameterDescription(
        "The maximum length of the input string (in bytes)",
        ParameterDescription.ConditionType.LOWER_LIMIT,
        "0"
    )
    var maxLength = 16
        set(value) {
            require(maxLength > 0) { "MaxLength must be positive, was $value" }
            field = value
        }

    val bitsMaxLength get() = maxLength * 8

    init {
        this.maxLength = maxLength
    }
}