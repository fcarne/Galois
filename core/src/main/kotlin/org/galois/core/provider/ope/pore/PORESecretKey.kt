package org.galois.core.provider.ope.pore

import java.nio.ByteBuffer
import javax.crypto.SecretKey

class PORESecretKey : SecretKey {
    private val encoded: ByteArray
    val q: Short
    val n: Byte
    val k: ByteArray

    constructor(q: Short, n: Byte, k: ByteArray) {
        this.q = q
        this.n = n
        this.k = k

        val buffer = ByteBuffer.allocate(FIXED_LENGTH + k.size)
        buffer.putShort(q).put(n).put(k)
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
        val buffer = ByteBuffer.wrap(encoded)

        this.q = buffer.short
        this.n = buffer.get()
        this.k = ByteArray(buffer.remaining())
        buffer[k]

        require(isKeyValid(q, n)) { getInvalidParameters(q, n) }

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = PORE_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    private fun isKeyValid(q: Short, n: Byte) = q >= 3 && n > 0

    private fun getInvalidParameters(q: Short, n: Byte): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        if (q < 3) error.append(" - q must be greater than 3, was $q").append("\n")
        if (n < 0) error.append(" - n must be positive. was $n").append("\n")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(256, 384, 512)
        const val FIXED_LENGTH = Short.SIZE_BYTES + Byte.SIZE_BYTES

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
    }
}