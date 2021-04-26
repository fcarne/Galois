package org.galois.core.provider.fpe

import org.galois.core.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

abstract class FPEParameterSpec(radix: Int = 10, tweak: ByteArray? = null) : AlgorithmParameterSpec {

    @ParameterDescription(
        "The radix of the input strings. This will also be the radix of the output",
        ParameterDescription.ConditionType.RANGE,
        "2..36"
    )
    var radix: Int = 10
        set(value) {
            require(value in 2..36) { "Radix must be in range 2..36 (inclusive), was $value" }
            field = value
        }
    abstract var tweak: ByteArray?

    abstract val minLen: Int
    abstract val maxLen: Int
    abstract val maxTLen: Int

    abstract fun generateRandomTweak(length: Int = maxLen): ByteArray

    init {
        this.radix = radix
    }
}