package org.galois.core.provider.fpe.ff3

import org.galois.core.provider.GaloisJCE
import org.galois.core.provider.description.ParameterDescription
import org.galois.core.provider.fpe.FPEParameterSpec
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.log
import kotlin.math.log2

class FF3ParameterSpec(radix: Int = 10, tweak: ByteArray? = null) : FPEParameterSpec(radix, tweak) {

    @ParameterDescription(
        "The tweak needed to encrypt/decrypt. It is represented by a hexadecimal string of exactly $MAX_T_LENGTH bytes",
        ParameterDescription.ConditionType.REGEX,
        "^(?:[A-Fa-f\\d]{2}){8}\$"
    )
    override var tweak: ByteArray? = null
        set(value) {
            value?.let {
                require(value.size == maxTLen) { "Tweak length must be $maxTLen, was ${value.size}" }
                field = value
            }
        }

    override val minLen get() = ceil(log(DOMAIN_MIN, radix.toDouble())).toInt()
    override val maxLen get() = 2 * floor(96 / log2(radix.toDouble())).toInt()
    override val maxTLen get() = MAX_T_LENGTH

    override fun generateRandomTweak(length: Int): ByteArray {
        tweak = GaloisJCE.random.generateSeed(MAX_T_LENGTH)
        return tweak!!
    }

    init {
        this.tweak = tweak
    }

    companion object {
        const val MAX_T_LENGTH = 8
        private const val DOMAIN_MIN = 100.0
    }
}