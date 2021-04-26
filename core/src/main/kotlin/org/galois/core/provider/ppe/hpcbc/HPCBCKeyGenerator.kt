package org.galois.core.provider.ppe.hpcbc

import org.galois.core.provider.GaloisJCE
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class HPCBCKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: HPCBCParameterSpec

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is HPCBCParameterSpec)
            throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${HPCBCParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        if (!this::parameterSpec.isInitialized) parameterSpec = HPCBCParameterSpec()

        require(HPCBCSecretKey.isKeySizeValid(keySize, parameterSpec.integrityCheck))
        { HPCBCSecretKey.getKeySizeError(keySize, parameterSpec.integrityCheck) }

        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = HPCBCParameterSpec()

        val keyPartsSizes = HPCBCSecretKey.getKeyPartsSizes(parameterSpec.integrityCheck)

        val keyGenerator = KeyGenerator.getInstance(HPCBCSecretKey.CIPHER_ALGORITHM)
        keyGenerator.init(keyPartsSizes.first)

        val cipherKey = keyGenerator.generateKey()
        val cipherTweak = secureRandom.generateSeed(keyPartsSizes.second / 8)
        val hashKey = RH2Hash.KeyGenerator().generateKey(keyPartsSizes.third / 8)

        return if (parameterSpec.integrityCheck) {
            val integrityKey = keyGenerator.generateKey()
            val integrityTweak = secureRandom.generateSeed(keyPartsSizes.second / 8)

            HPCBCSecretKey(cipherKey.encoded, cipherTweak, integrityKey.encoded, integrityTweak, hashKey)
        } else HPCBCSecretKey(cipherKey.encoded, cipherTweak, hashKey)

    }
}