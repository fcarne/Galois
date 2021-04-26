package org.galois.crypto.provider.ppe.cryptopan

import java.nio.ByteBuffer
import javax.crypto.SecretKey

class CryptoPAnSecretKey : SecretKey {
    private val encoded: ByteArray
    val cipherKey: ByteArray
    val padSeed: ByteArray

    constructor(cipherKey: ByteArray, padSeed: ByteArray) {
        this.cipherKey = cipherKey
        this.padSeed = padSeed

        val buffer = ByteBuffer.allocate(cipherKey.size + padSeed.size)
        buffer.put(cipherKey).put(padSeed)
        this.encoded = buffer.array()
    }

    constructor(encoded: ByteArray) {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }

        val keyPartsSizes = getKeyPartsSizes(encoded.size)
        val buffer = ByteBuffer.wrap(encoded)

        this.cipherKey = ByteArray(keyPartsSizes.first)
        this.padSeed = ByteArray(keyPartsSizes.second)
        buffer[cipherKey][padSeed]

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = CRYPTOPAN_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    companion object {
        const val CIPHER_ALGORITHM = "AES"
        val KEY_SIZES = intArrayOf(256, 384, 512)

        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
        fun getKeyPartsSizes(len: Int) = Pair(len / 2, len / 2)
    }
}