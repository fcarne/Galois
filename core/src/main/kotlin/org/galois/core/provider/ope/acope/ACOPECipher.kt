package org.galois.core.provider.ope.acope

import org.galois.core.provider.GaloisCipher
import org.galois.core.provider.util.FluentBitSet
import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import kotlin.math.pow

const val ACOPE_ALGORITHM_NAME = "ArithmeticCoding"

class ACOPECipher : GaloisCipher() {
    private lateinit var ratios: Array<Pair<Byte, Byte>>
    private var n: Byte = 0
    private var k: Int = 0
    private var domain: Long = 0
    private lateinit var maxCipherValue: BigInteger

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val acopeSecretKey = ACOPESecretKey(keyBytes)

        ratios = acopeSecretKey.ratios
        n = acopeSecretKey.n
        k = acopeSecretKey.k

        domain = 2.0.pow(n.toInt()).toLong()
        maxCipherValue = BigInteger.TWO.pow(k)
    }

    override fun engineGetOutputSize(inputLen: Int) =
        if (opMode == Cipher.ENCRYPT_MODE && k > 0) k
        else if (opMode == Cipher.DECRYPT_MODE) Long.SIZE_BYTES
        else 0

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        var a = BigDecimal.ZERO
        var b = BigDecimal.ONE

        if (opMode == Cipher.ENCRYPT_MODE) {
            val num = ByteBuffer.wrap(input).long
            require(num in 0..domain) { "Plaintext must be in range 0..$domain, was $num" }

            val cipher = FluentBitSet(k)
            val x = num.toBigDecimal().divide(domain.toBigDecimal())

            for (i in 0 until k) {
                val (p, q) = ratios[i % ratios.size]
                val s = a + (b - a) * (p.toDouble() / (p + q)).toBigDecimal()
                if (s > x) {
                    b = s
                } else {
                    cipher[k - i - 1] = true
                    a = s
                }
            }

            val cipherArray = cipher.toByteArray()
            System.arraycopy(cipherArray, 0, output, output.size - cipherArray.size, cipherArray.size)

        } else if (opMode == Cipher.DECRYPT_MODE) {
            val c = BigInteger(input)
            require(c >= BigInteger.ZERO && c <= maxCipherValue) { "Ciphertext must be in range 0..$maxCipherValue, was $c" }

            val sigma = FluentBitSet.valueOf(input)
            for (i in 0 until k) {
                val (p, q) = ratios[i % ratios.size]
                val s = a + (b - a) * (p.toDouble() / (p + q)).toBigDecimal()
                if (!sigma.getValue(k - i - 1)) b = s else a = s
            }

            // ceil instead of floor + 1 because 0 or if all ratios are 1 : 1  2^n * a is already an int
            val num = (domain.toBigDecimal() * a).setScale(0, RoundingMode.CEILING).toLong()

            val plaintextArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(num).array()
            System.arraycopy(plaintextArray, 0, output, 0, output.size)
        }
        return inputLen
    }

}