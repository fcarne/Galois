package org.galois.core.provider.ope.acope

import org.galois.core.provider.GaloisJCE
import java.security.InvalidAlgorithmParameterException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import kotlin.math.max
import kotlin.math.pow

class ACOPEKeyGenerator : KeyGeneratorSpi() {
    private lateinit var secureRandom: SecureRandom
    private lateinit var parameterSpec: ACOPEParameterSpec

    private var keySize: Int = ACOPESecretKey.KEY_SIZES[0]

    override fun engineInit(secureRandom: SecureRandom) {
        this.secureRandom = secureRandom
    }

    @Throws(InvalidAlgorithmParameterException::class)
    override fun engineInit(algorithmParameterSpec: AlgorithmParameterSpec, secureRandom: SecureRandom) {
        if (algorithmParameterSpec !is ACOPEParameterSpec)
            throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${ACOPEParameterSpec::class.java.name}")

        parameterSpec = algorithmParameterSpec
        engineInit(secureRandom)
    }

    override fun engineInit(keySize: Int, secureRandom: SecureRandom) {
        require(ACOPESecretKey.isKeySizeValid(keySize)) { ACOPESecretKey.getKeySizeError(keySize) }

        this.keySize = keySize
        engineInit(secureRandom)
    }

    override fun engineGenerateKey(): SecretKey {
        if (!this::secureRandom.isInitialized) secureRandom = GaloisJCE.random
        if (!this::parameterSpec.isInitialized) parameterSpec = ACOPEParameterSpec()

        val ratiosNumber = (keySize / 8 - ACOPESecretKey.FIXED_LENGTH) / (2 * Byte.SIZE_BYTES)
        val ratios = Array<Pair<Byte, Byte>>(ratiosNumber) { Pair(0, 0) }
        val n = parameterSpec.n
        var k: Int

        do {
            for (i in ratios.indices) {
                val p = (secureRandom.nextInt(126) + 1).toByte()
                val q = (secureRandom.nextInt(126) + 1).toByte()
                ratios[i] = Pair(p, q)
            }

            k = 0
            var product = 1.0
            do {
                val (p, q) = ratios[k++ % ratiosNumber]
                product *= max(p.toDouble(), q.toDouble()) / (p + q)
            } while (k <= 255 && product > 0.5.pow(n.toInt()))
        } while (k > 255)
        if (k < ratiosNumber) k = ratiosNumber
        return ACOPESecretKey(ratios, n, k)
    }
}