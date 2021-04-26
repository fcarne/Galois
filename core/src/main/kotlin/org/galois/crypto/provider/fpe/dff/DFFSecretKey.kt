package org.galois.crypto.provider.fpe.dff

import org.galois.crypto.provider.fpe.ff3.FF3SecretKey
import javax.crypto.spec.SecretKeySpec

class DFFSecretKey(encoded: ByteArray) : SecretKeySpec(encoded, DFF_ALGORITHM_NAME) {

    init {
        require(FF3SecretKey.isKeySizeValid(encoded.size * 8)) { FF3SecretKey.getKeySizeError(encoded.size * 8) }
    }

    companion object {
        const val CIPHER_KEY_ALGORITHM = "AES"
        const val CIPHER_ALGORITHM = "AES/ECB/NoPadding"

        val KEY_SIZES = intArrayOf(128, 192, 256)
        fun isKeySizeValid(len: Int) = len in KEY_SIZES
        fun getKeySizeError(len: Int) = "Key size can only be ${KEY_SIZES.joinToString()}, was $len"
    }
}