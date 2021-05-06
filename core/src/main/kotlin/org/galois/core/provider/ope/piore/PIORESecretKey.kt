package org.galois.core.provider.ope.piore

import java.nio.ByteBuffer
import javax.crypto.SecretKey

class PIORESecretKey : SecretKey {
    private val encoded: ByteArray
    val m: Short
    val n: Byte
    val k: ByteArray

    constructor(m: Short, n: Byte, k: ByteArray) {
        this.m = m
        this.n = n
        this.k = k

        val buffer = ByteBuffer.allocate(FIXED_LENGTH + k.size)
        buffer.putShort(m).put(n).put(k)
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
        val buffer = ByteBuffer.wrap(encoded)

        this.m = buffer.short
        this.n = buffer.get()
        this.k = ByteArray(buffer.remaining())
        buffer[k]

        require(isKeyValid(m, n)) { getInvalidParameters(m, n) }

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = PIORE_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    private fun isKeyValid(m: Short, n: Byte) = m in MIN_M..MAX_M && n > 0

    private fun getInvalidParameters(m: Short, n: Byte): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        if (m !in MIN_M..MAX_M) error.append(" - m must be in range $MIN_M..$MAX_M, was $m").append("\n")
        if (n < 0) error.append(" - n must be positive. was $n").append("\n")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(128, 192, 256, 384, 512)
        const val FIXED_LENGTH = Short.SIZE_BYTES + Byte.SIZE_BYTES

        const val MAX_M = Short.MAX_VALUE / 2
        const val MIN_M = 512

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"

    }
}