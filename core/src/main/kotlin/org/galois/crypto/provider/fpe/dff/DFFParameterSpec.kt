package org.galois.crypto.provider.fpe.dff

import crypto.provider.GaloisJCE
import org.galois.crypto.provider.fpe.FPEParameterSpec
import org.galois.crypto.provider.description.ParameterDescription
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.log
import kotlin.math.log2

class DFFParameterSpec(radix: Int = 10, tweak: ByteArray? = null) : FPEParameterSpec(radix, tweak) {

    @ParameterDescription(
        "The tweak needed to encrypt/decrypt. It is represented by a hexadecimal string of maximum $MAX_T_LENGTH bytes",
        ParameterDescription.ConditionType.REGEX,
        "^(?:[A-Fa-f\\d]{2}){1,13}\$"
    )
    override var tweak: ByteArray? = null
        set(value) {
            value?.let {
                require(value.size <= maxTLen) { "Tweak length must be equal or less than $maxTLen, was ${value.size}" }
                field = value
            }
        }

    override val minLen get() = ceil(log(DOMAIN_MIN, radix.toDouble())).toInt()

    override val maxLen
        get() = if (radix and radix - 1 == 0) 2 * floor(120 / log2(radix.toDouble())).toInt()
        else 2 * floor(98 / log2(radix.toDouble())).toInt()

    override val maxTLen get() = MAX_T_LENGTH

    override fun generateRandomTweak(length: Int): ByteArray {
        tweak = GaloisJCE.random.generateSeed(MAX_T_LENGTH)
        return tweak!!
    }


    companion object {
        private const val DOMAIN_MIN = 100.0
        const val MAX_T_LENGTH = 13
    }
}