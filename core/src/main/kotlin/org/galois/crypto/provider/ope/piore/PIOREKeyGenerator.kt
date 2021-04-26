package crypto.provider.ope.piore

import crypto.provider.GaloisJCE
import org.galois.crypto.provider.ope.piore.PIOREParameterSpec
import org.galois.crypto.provider.ope.piore.PIORESecretKey
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class PIOREKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: PIOREParameterSpec

    private var keySize: Int = PIORESecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is PIOREParameterSpec)
            throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${PIOREParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(PIORESecretKey.isKeySizeValid(keySize)) { PIORESecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = PIOREParameterSpec()

        val k = ByteArray(keySize / 8 - PIORESecretKey.FIXED_LENGTH)
        secureRandom.nextBytes(k)

        val m = (secureRandom.nextInt(24 - 12) + 12).toByte()
        return PIORESecretKey(m, parameterSpec.d, k)
    }
}