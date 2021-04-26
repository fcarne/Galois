package org.galois.core.provider.ope.piore

import java.nio.ByteBuffer
import javax.crypto.SecretKey

class PIORESecretKey : SecretKey {
    private val encoded: ByteArray
    val m: Byte
    val d: Byte
    val k: ByteArray

    constructor(m: Byte, d: Byte, k: ByteArray) {
        this.m = m
        this.d = d
        this.k = k

        val buffer = ByteBuffer.allocate(FIXED_LENGTH + k.size)
        buffer.put(m).put(d).put(k)
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
        val buffer = ByteBuffer.wrap(encoded)

        this.m = buffer.get()
        this.d = buffer.get()
        this.k = ByteArray(buffer.remaining())
        buffer[k]

        require(isKeyValid(m, d)) { getInvalidParameters(m, d) }

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = PIORE_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    private fun isKeyValid(m: Byte, n: Byte) = m >= 12 && n > 0

    private fun getInvalidParameters(m: Byte, n: Byte): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        if (m < 12) error.append(" - m must be greater than 12 in order to avoid collision, was $m").append("\n")
        if (n < 0) error.append(" - d must be positive. was $n").append("\n")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(128, 192, 256, 384, 512)
        const val FIXED_LENGTH = 2 * Byte.SIZE_BYTES

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"

    }
}