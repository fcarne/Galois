package org.galois.core.provider.ope.piore

import org.galois.core.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class PIOREParameterSpec(d: Byte = 8) : AlgorithmParameterSpec {
    @ParameterDescription(
        "The binary logarithm of the upper bound of the domain",
        ParameterDescription.ConditionType.RANGE,
        "0..127"
    )
    var d: Byte = 8
        set(value) {
            require(value > 0) { "D must be positive, was $d" }
            field = value
        }

    init {
        this.d = d
    }
}