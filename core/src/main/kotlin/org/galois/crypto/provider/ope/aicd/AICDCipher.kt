package org.galois.crypto.provider.ope.aicd

import crypto.provider.GaloisCipher
import org.galois.crypto.provider.ope.aicd.AICDSecretKey
import java.math.BigDecimal
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.*
import javax.crypto.Cipher
import kotlin.math.pow

const val AICD_ALGORITHM_NAME = "CommonDivisor"

class AICDCipher : GaloisCipher() {

    private lateinit var secureRandom: SecureRandom
    private lateinit var k: BigInteger
    private lateinit var kPow: BigInteger
    private var kBytesLength: Int = 0

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode
        this.secureRandom = secureRandom

        val keyBytes: ByteArray = getKeyBytes(key)
        val aicdSecretKey = AICDSecretKey(keyBytes)

        k = aicdSecretKey.k
        kPow = BigDecimal.valueOf(k.toDouble().pow(3.0 / 4)).toBigInteger()
        kBytesLength = k.toByteArray().size
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

            val r = BigInteger(k.bitLength(), secureRandom).mod(k.subtract(BigInteger.TWO.multiply(kPow))).add(kPow)
            val c = BigInteger.valueOf(m).multiply(k).add(r)

            val cipherArray = c.toByteArray()
            System.arraycopy(cipherArray, 0, output, output.size - cipherArray.size, cipherArray.size)
        } else if (opMode == Cipher.DECRYPT_MODE) {
            val c = BigInteger(input)
            val m = c.divide(k).toLong()

            val plaintextArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(m).array()
            System.arraycopy(plaintextArray, 0, output, 0, output.size)
        }
        return inputLen
    }

}