package org.galois.core.provider.ope.piore

import org.galois.core.provider.GaloisCipher
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

const val PIORE_ALGORITHM_NAME = "PIOre"

class PIORECipher : GaloisCipher() {
    private lateinit var m: BigInteger
    private var n: Byte = 0
    private var domain: Long = 0

    private lateinit var mPowerN: BigInteger
    private var mPowerNBytesLength = 0

    private lateinit var mac: Mac

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode
        val keyBytes = getKeyBytes(key)

        val pioreSecretKey = PIORESecretKey(keyBytes)
        m = pioreSecretKey.m.toLong().toBigInteger()
        n = pioreSecretKey.n

        domain = 2.0.pow(n.toInt()).toLong()

        mac = Mac.getInstance("HmacSha256")
        mac.init(SecretKeySpec(pioreSecretKey.k, mac.algorithm))

        mPowerN = m.pow(n.toInt())
        mPowerNBytesLength = mPowerN.toByteArray().size
    }

    override fun engineGetOutputSize(inputLen: Int): Int =
        if (opMode == Cipher.ENCRYPT_MODE && mPowerNBytesLength > 0) mPowerNBytesLength
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
            val b = ByteBuffer.wrap(input).long
            require(b in 0..domain) { "Plaintext must be in range 0..$domain, was $b" }

            var cipher = BigInteger.ZERO

            for (i in 1..n) {
                val bI = (b shr n - i and 1).toInt()
                val uI = f(i, b, bI)
                cipher += m.pow(n - i) * uI
            }

            val cipherArray = cipher.toByteArray()
            System.arraycopy(cipherArray, 0, output, output.size - cipherArray.size, cipherArray.size)

        } else if (opMode == Cipher.DECRYPT_MODE) {
            var c = BigInteger(input)
            require(c >= BigInteger.ZERO && c < mPowerN) { "Ciphertext must be in range 0..$mPowerN - 1, was $c" }

            var b: Long = 0
            val u = Array(n.toInt()) { BigInteger.ZERO }

            for (i in n - 1 downTo 0) {
                val quotientAndRemainder = c.divideAndRemainder(m)
                c = quotientAndRemainder[0]
                u[i] = quotientAndRemainder[1]
            }

            for (i in 1..n) {
                val uI = f(i, b, 0)
                if (u[i - 1] != uI) b = b or (1L shl n - i)
            }

            if (c != BigInteger.ZERO) b = Long.MIN_VALUE

            val plaintextArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(b).array()
            System.arraycopy(plaintextArray, 0, output, 0, output.size)

        }
        return inputLen
    }

    private fun f(i: Int, b: Long, bI: Int): BigInteger {
        val shift = n - i + 1
        val x = b shr shift shl shift
        return (prf(i, x) + bI.toBigInteger()).mod(m)
    }

    private fun prf(i: Int, b: Long): BigInteger {
        val message = ByteBuffer.allocate(Int.SIZE_BYTES + Long.SIZE_BYTES).putInt(i).putLong(b).array()
        return BigInteger(mac.doFinal(message))
    }

}