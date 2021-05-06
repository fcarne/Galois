package org.galois.core.provider.ope.aicd

import java.math.BigInteger
import javax.crypto.SecretKey

class AICDSecretKey : SecretKey {
    private val encoded: ByteArray
    val k: BigInteger

    constructor(k: BigInteger) {
        this.k = k
        val kBytes = k.toByteArray()
        this.encoded = kBytes
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }

        this.k = BigInteger(encoded)

        require(isKeyValid(k)) { getInvalidParameters(k) }
        this.encoded = encoded.clone()
    }

    override fun getAlgorithm(): String = AICD_ALGORITHM_NAME

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray = encoded.clone()

    private fun isKeyValid(k: BigInteger) = k > BigInteger.ZERO

    private fun getInvalidParameters(k: BigInteger): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        if (k <= BigInteger.ZERO) error.append(" - k must be positive, was $k")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(128, 192, 256, 384, 512)
        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
    }

}

