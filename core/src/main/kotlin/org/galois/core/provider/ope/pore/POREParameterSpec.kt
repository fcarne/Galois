package org.galois.core.provider.ope.pore

import org.galois.core.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class POREParameterSpec(n: Byte = 8, q: Short = 1024) : AlgorithmParameterSpec {
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

    @ParameterDescription(
        "The base in which the ciphertext will be represented",
        ParameterDescription.ConditionType.RANGE,
        "3..$MAX_Q"
    )
    var q: Short = 1024
        set(value) {
            require(value in 3..MAX_Q) { "q must be in range 3..$MAX_Q, was $value" }
            field = value
        }

    init {
        this.n = n
        this.q = q
    }

    companion object {
        const val MAX_Q = 16384
    }
}