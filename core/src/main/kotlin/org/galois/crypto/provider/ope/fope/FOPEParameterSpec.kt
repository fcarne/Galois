package org.galois.crypto.provider.ope.fope

import org.galois.crypto.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class FOPEParameterSpec(tau: Int = 16, d: Byte = 8) : AlgorithmParameterSpec {

    @ParameterDescription(
        "The minimum distance between two encrypted values",
        ParameterDescription.ConditionType.LOWER_LIMIT,
        "1"
    )
    var tau: Int = 16
        set(value) {
            require(value > 1) { "Tau must be at least 2, was $value" }
            field = value
        }

    @ParameterDescription(
        "The binary logarithm of the upper bound of the domain",
        ParameterDescription.ConditionType.RANGE,
        "0..127"
    )
    var d: Byte = 8
        set(value) {
            require(value > 0) { "D must be greater than 0, was $value" }
            field = value
        }

    init {
        this.tau = tau
        this.d = d
    }
}