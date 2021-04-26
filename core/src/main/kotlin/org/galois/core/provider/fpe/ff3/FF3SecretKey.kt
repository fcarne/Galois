package org.galois.core.provider.fpe.ff3

import javax.crypto.spec.SecretKeySpec

class FF3SecretKey(encoded: ByteArray) : SecretKeySpec(encoded, FF3_ALGORITHM_NAME) {

    init {
        require(isKeySizeValid(encoded.size * 8)) { getKeySizeError(encoded.size * 8) }
    }

    companion object {
        const val CIPHER_KEY_ALGORITHM = "AES"
        const val CIPHER_ALGORITHM = "AES/ECB/NoPadding"

        val KEY_SIZES = intArrayOf(128, 192, 256)
        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
    }
}