package org.galois.crypto.provider.fpe.dff

import crypto.provider.GaloisJCE
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey


class DFFKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom

    private var keySize: Int = DFFSecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) =
        throw InvalidAlgorithmParameterException("$DFF_ALGORITHM_NAME key generation does not take any parameters")

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(DFFSecretKey.isKeySizeValid(keySize)) { DFFSecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random

        val keyBytes = ByteArray(keySize / 8)
        secureRandom.nextBytes(keyBytes)
        return DFFSecretKey(keyBytes)
    }
}