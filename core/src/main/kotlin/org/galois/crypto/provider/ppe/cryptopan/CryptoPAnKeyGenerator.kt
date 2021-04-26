package org.galois.crypto.provider.ppe.cryptopan

import crypto.provider.GaloisJCE
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class CryptoPAnKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom

    private var keySize: Int = CryptoPAnSecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) =
        throw InvalidAlgorithmParameterException("$CRYPTOPAN_ALGORITHM_NAME key generation does not take any parameters")

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(CryptoPAnSecretKey.isKeySizeValid(keySize)) { CryptoPAnSecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random

        val keyPartsSizes = CryptoPAnSecretKey.getKeyPartsSizes(keySize)
        val keyGenerator = KeyGenerator.getInstance(CryptoPAnSecretKey.CIPHER_ALGORITHM)
        keyGenerator.init(keyPartsSizes.first)

        val cipherKey = keyGenerator.generateKey()
        val padSeed = secureRandom.generateSeed(keyPartsSizes.second / 8)

        return CryptoPAnSecretKey(cipherKey.encoded, padSeed)

    }
}