package org.galois.core.provider.ope.acope

import org.galois.core.provider.fpe.dff.DFFSecretKey
import java.nio.ByteBuffer
import javax.crypto.SecretKey

class ACOPESecretKey : SecretKey {
    private val encoded: ByteArray
    val ratios: Array<Pair<Byte, Byte>>
    val n: Byte
    val k: Int

    constructor(ratios: Array<Pair<Byte, Byte>>, n: Byte, k: Int) {
        this.ratios = ratios
        this.n = n
        this.k = k

        val buffer = ByteBuffer.allocate(2 * Byte.SIZE_BYTES * ratios.size + FIXED_LENGTH)
        ratios.forEach { buffer.put(it.first).put(it.second) }
        buffer.put(n).put((k - 128).toByte())
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
        val buffer = ByteBuffer.wrap(encoded)

        val ratiosNumber = (encoded.size - FIXED_LENGTH) / (2 * Byte.SIZE_BYTES)

        this.ratios = Array(ratiosNumber) { Pair(0, 0) }

        for (i in ratios.indices) ratios[i] = Pair(buffer.get(), buffer.get())

        this.n = buffer.get()
        this.k = buffer.get() + 128
        require(isKeyValid(ratios, n, k)) { getInvalidParameters(ratios, n, k) }

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = ACOPE_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    private fun isKeyValid(ratios: Array<Pair<Byte, Byte>>, n: Byte, k: Int) =
        ratios.all { it.first > 0 && it.second > 0 } && n > 0 && k > 0

    private fun getInvalidParameters(ratios: Array<Pair<Byte, Byte>>, n: Byte, k: Int): String {
        val error = StringBuilder().append("Invalid parameters:\n")
        ratios.forEachIndexed { index, it ->
            if (it.first <= 0) error.append("p$index must be positive, was ${it.first}").append("\n")
            if (it.second <= 0) error.append("q$index must be positive, was ${it.second}").append("\n")
        }
        if (n < 0) error.append(" - n must be positive, was $n").append("\n")
        if (k < 0) error.append(" - k must be positive, was $k").append("\n")
        return error.toString()
    }

    companion object {
        val KEY_SIZES = intArrayOf(256, 384, 512)
        const val FIXED_LENGTH = 2 * Byte.SIZE_BYTES

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
    }
}