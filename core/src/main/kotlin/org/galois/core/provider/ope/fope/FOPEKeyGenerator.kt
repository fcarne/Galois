package org.galois.core.provider.ope.fope

import org.galois.core.provider.GaloisJCE
import java.math.BigDecimal
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import kotlin.math.ceil

class FOPEKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: FOPEParameterSpec

    private var keySize: Int = FOPESecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is FOPEParameterSpec)
            throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${FOPEParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(FOPESecretKey.isKeySizeValid(keySize)) { FOPESecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = FOPEParameterSpec()

        val alpha = 0.5 * secureRandom.nextDouble()
        val beta = 1.0 - alpha
        val e = secureRandom.nextDouble() * alpha
        val n = ceil(parameterSpec.tau.toDouble()) / (beta * BigDecimal.valueOf(e).pow(parameterSpec.d.toInt())
            .toDouble())
        val k = ByteArray(keySize / 8 - FOPESecretKey.FIXED_LENGTH)
        secureRandom.nextBytes(k)

        return FOPESecretKey(n, alpha, e, parameterSpec.d, k)
    }
}