package org.galois.core.provider.ope.aicd

import org.galois.core.provider.GaloisCipher
import java.math.BigDecimal
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import kotlin.math.pow
import kotlin.math.roundToLong

const val AICD_ALGORITHM_NAME = "CommonDivisor"

class AICDCipher : GaloisCipher() {

    private lateinit var secureRandom: SecureRandom
    private lateinit var k: BigInteger
    private lateinit var kThreeQuarters: BigInteger
    private var kBytesLength: Int = 0

    private var domain: Long = 0
    private lateinit var maxCipherValue: BigInteger

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode
        this.secureRandom = secureRandom

        val keyBytes: ByteArray = getKeyBytes(key)
        val aicdSecretKey = AICDSecretKey(keyBytes)

        k = aicdSecretKey.k
        kThreeQuarters = BigDecimal.valueOf(k.toDouble().pow(3.0 / 4)).toBigInteger()
        kBytesLength = k.toByteArray().size

        domain = k.toDouble().pow(3.0 / 8.0).roundToLong()
        maxCipherValue = BigInteger.valueOf(domain).multiply(k).add(k.subtract(kThreeQuarters))
    }

    override fun engineGetOutputSize(inputLen: Int): Int =
        if (opMode == Cipher.ENCRYPT_MODE && kBytesLength > 0) kBytesLength + inputLen + 1
        else if (opMode == Cipher.DECRYPT_MODE) Long.SIZE_BYTES
        else 0

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        if (opMode == Cipher.ENCRYPT_MODE) {
            val m = ByteBuffer.wrap(input).long
            require(m in 0..domain) { "Plaintext must be in range 0..$domain, was $m" }

            val r = BigInteger(k.bitLength(), secureRandom).mod(k.subtract(BigInteger.TWO.multiply(kThreeQuarters)))
                .add(kThreeQuarters)
            val c = BigInteger.valueOf(m).multiply(k).add(r)

            val cipherArray = c.toByteArray()
            System.arraycopy(cipherArray, 0, output, output.size - cipherArray.size, cipherArray.size)
        } else if (opMode == Cipher.DECRYPT_MODE) {
            val c = BigInteger(input)
            require(c > BigInteger.ZERO && c <= maxCipherValue) { "Ciphertext must be in range 0..$maxCipherValue, was $c" }

            val m = c.divide(k).toLong()

            val plaintextArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(m).array()
            System.arraycopy(plaintextArray, 0, output, 0, output.size)
        }
        return inputLen
    }

}