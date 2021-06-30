package org.galois.core.provider.ope.pore

import org.galois.core.provider.GaloisJCE
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class POREKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: POREParameterSpec

    private var keySize: Int = PORESecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is POREParameterSpec)
            throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${POREParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(PORESecretKey.isKeySizeValid(keySize)) { PORESecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = POREParameterSpec()

        val k = ByteArray(keySize / 8 - PORESecretKey.FIXED_LENGTH)
        secureRandom.nextBytes(k)

        return PORESecretKey(parameterSpec.q, parameterSpec.n, k)
    }
}