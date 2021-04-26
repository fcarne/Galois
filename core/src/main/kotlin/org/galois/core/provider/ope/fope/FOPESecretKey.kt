package org.galois.core.provider.ope.fope

import org.galois.core.provider.fpe.dff.DFFSecretKey
import java.nio.ByteBuffer
import javax.crypto.SecretKey

class FOPESecretKey : SecretKey {
    private val encoded: ByteArray
    val n: Double
    val alpha: Double
    val e: Double
    val d: Byte
    val k: ByteArray

    constructor(n: Double, alpha: Double, e: Double, d: Byte, k: ByteArray) {
        this.n = n
        this.alpha = alpha
        this.e = e
        this.d = d
        this.k = k

        val buffer = ByteBuffer.allocate(FIXED_LENGTH + k.size)
        buffer.putDouble(n).putDouble(alpha).putDouble(e).put(d).put(k)
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
        val buffer = ByteBuffer.wrap(encoded)

        this.n = buffer.double
        this.alpha = buffer.double
        this.e = buffer.double
        this.d = buffer.get()
        this.k = ByteArray(buffer.remaining())
        buffer[k]

        require(isKeyValid(n, alpha, e, d)) { getInvalidParameters(n, alpha, e, d) }

        this.encoded = encoded.clone()
    }

    val beta get() = 1 - alpha

    override fun getAlgorithm() = FOPE_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    private fun isKeyValid(n: Double, alpha: Double, e: Double, d: Byte) =
        (n > 0 && alpha > 0 && alpha <= 0.5 && e > 0 && e <= alpha && d > 0)

    private fun getInvalidParameters(n: Double, alpha: Double, e: Double, d: Byte): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        if (n < 0) error.append(" - n must be positive, was $n").append("\n")
        if (alpha < 0 || alpha > 0.5) error.append(" - alpha must be between 0.0 and 0.5, was $alpha").append("\n")
        if (e < 0 || e > alpha) error.append(" - e must be between 0.0 and $alpha (alpha), was $e").append("\n")
        if (d < 0) error.append(" - d must be positive, was $d").append("\n")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(256, 384, 512)
        const val FIXED_LENGTH = Double.SIZE_BYTES * 3 + Byte.SIZE_BYTES

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${DFFSecretKey.KEY_SIZES.joinToString()}, was $len"
    }
}