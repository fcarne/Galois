package org.galois.core.provider.ppe.hpcbc

import java.nio.ByteBuffer
import javax.crypto.SecretKey

class HPCBCSecretKey : SecretKey {
    private val encoded: ByteArray
    val cipherKey: ByteArray
    val cipherTweak: ByteArray
    val integrityKey: ByteArray
    val integrityTweak: ByteArray
    val hashKey: ByteArray

    private constructor(
        cipherKey: ByteArray,
        cipherTweak: ByteArray,
        integrityKey: ByteArray,
        integrityTweak: ByteArray,
        hashKey: ByteArray,
        integrityCheck: Boolean
    ) {
        this.cipherKey = cipherKey
        this.cipherTweak = cipherTweak
        this.integrityKey = integrityKey
        this.integrityTweak = integrityTweak
        this.hashKey = hashKey

        val buffer =
            if (integrityCheck) ByteBuffer.allocate(KEY_SIZES[1] / 8) else ByteBuffer.allocate(KEY_SIZES[0] / 8)
        buffer.put(cipherKey).put(cipherTweak).put(hashKey)
        if (integrityCheck) buffer.put(integrityKey).put(integrityTweak)

        this.encoded = buffer.array()
    }

    constructor(
        cipherKey: ByteArray, cipherTweak: ByteArray, hashKey: ByteArray
    ) : this(cipherKey, cipherTweak, ByteArray(0), ByteArray(0), hashKey, false)

    constructor(
        cipherKey: ByteArray,
        cipherTweak: ByteArray,
        integrityKey: ByteArray,
        integrityTweak: ByteArray,
        hashKey: ByteArray
    ) : this(cipherKey, cipherTweak, integrityKey, integrityTweak, hashKey, true)

    constructor(encoded: ByteArray, integrityCheck: Boolean) {
        require(isKeySizeValid(encoded.size * 8, integrityCheck)) { getKeySizeError(encoded.size * 8, integrityCheck) }
        val buffer = ByteBuffer.wrap(encoded)

        val keyPartsSizes = getKeyPartsSizes(integrityCheck)
        this.cipherKey = ByteArray(keyPartsSizes.first / 8)
        this.cipherTweak = ByteArray(keyPartsSizes.second / 8)
        this.integrityKey = ByteArray(keyPartsSizes.first / 8)
        this.integrityTweak = ByteArray(keyPartsSizes.second / 8)
        this.hashKey = ByteArray(keyPartsSizes.third / 8)

        buffer[cipherKey][cipherTweak][hashKey]
        if (integrityCheck) buffer[integrityKey][integrityTweak]

        this.encoded = encoded.clone()
    }

    override fun getAlgorithm() = HPCBC_ALGORITHM_NAME

    override fun getFormat() = "RAW"

    override fun getEncoded() = encoded.clone()

    companion object {
        const val CIPHER_ALGORITHM = "FF3"
        val KEY_SIZES = intArrayOf(256, 512)

        fun isKeySizeValid(len: Int, integrityCheck: Boolean) = if (integrityCheck) len == KEY_SIZES[1]
        else len == KEY_SIZES[0]

        fun getKeySizeError(len: Int, integrityCheck: Boolean) =
            if (integrityCheck) " With integrity check key size can only be ${KEY_SIZES[1]}, was $len"
            else "Without integrity check key size can only be ${KEY_SIZES[0]}, was $len"

        fun getKeyPartsSizes(integrityCheck: Boolean) = if (integrityCheck) Triple(128, 64, 128)
        else Triple(128, 64, 64)

    }
}