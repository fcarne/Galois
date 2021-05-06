package org.galois.core.provider.ope.piore

import org.galois.core.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class PIOREParameterSpec(n: Byte = 8) : AlgorithmParameterSpec {
    @ParameterDescription(
        "The binary logarithm of the upper bound of the domain",
        ParameterDescription.ConditionType.RANGE,
        "1..63"
    )
    var n: Byte = 8
        set(value) {
            require(value in 1..63) { "N must be in range 1..63, was $value" }
            field = value
        }

    init {
        this.n = n
    }
}