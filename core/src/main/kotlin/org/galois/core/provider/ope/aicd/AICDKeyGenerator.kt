package org.galois.core.provider.ope.aicd

import org.galois.core.provider.GaloisJCE
import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class AICDKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: AICDParameterSpec

    private var keySize: Int = AICDSecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is AICDParameterSpec)
            throw InvalidAlgorithmParameterException("ParametersSpec must be of type ${AICDParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        if (!this::parameterSpec.isInitialized) parameterSpec = AICDParameterSpec()

        require(AICDSecretKey.isKeySizeValid(keySize)) { AICDSecretKey.getKeySizeError(keySize) }
        require(keySize >= parameterSpec.minKeySize) { "Key size must be at least ${parameterSpec.minKeySize}, was $keySize" }

        this.keySize = keySize
    }


    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = AICDParameterSpec()

        // -2 to avoid sign byte
        val lambda = keySize - 2
        val k =
            BigInteger(lambda, secureRandom).mod(BigInteger.TWO.pow(lambda + 1).subtract(BigInteger.TWO.pow(lambda)))
                .add(BigInteger.TWO.pow(lambda))

        return AICDSecretKey(k)
    }
}