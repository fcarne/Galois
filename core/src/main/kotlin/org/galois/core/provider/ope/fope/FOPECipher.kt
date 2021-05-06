package org.galois.core.provider.ope.fope

import org.galois.core.provider.GaloisCipher
import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode
import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

const val FOPE_ALGORITHM_NAME = "FastOPE"

class FOPECipher : GaloisCipher() {
    private lateinit var n: BigInteger
    private var d: Byte = 0
    private var domain: Long = 0
    private lateinit var infLimitF: Array<BigInteger>
    private lateinit var supLimitF: Array<BigInteger>
    private var nBytesLength = 0

    private lateinit var mac: Mac

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val fopeSecretKey = FOPESecretKey(keyBytes)

        val alpha = fopeSecretKey.alpha.toBigDecimal()
        val beta = fopeSecretKey.beta.toBigDecimal()
        val bigN = fopeSecretKey.n.toBigDecimal()
        n = bigN.toBigInteger()
        val e = fopeSecretKey.e.toBigDecimal()
        d = fopeSecretKey.d
        domain = 2.0.pow(d.toInt()).toLong()

        infLimitF = Array(d + 1) { BigInteger.ZERO }
        supLimitF = Array(d + 1) { BigInteger.ZERO }

        for (i in 0..d) {
            val factor = e.pow(i) * bigN
            infLimitF[i] = (alpha * factor).setScale(0, RoundingMode.FLOOR).toBigInteger()
            supLimitF[i] = (beta * factor).setScale(0, RoundingMode.CEILING).toBigInteger()
        }
        infLimitF[d.toInt()] = BigInteger.ONE

        mac = Mac.getInstance("HmacSha256")
        mac.init(SecretKeySpec(fopeSecretKey.k, mac.algorithm))

        nBytesLength = n.toByteArray().size
    }

    override fun engineGetOutputSize(inputLen: Int) =
        if (opMode == Cipher.ENCRYPT_MODE && nBytesLength > 0) nBytesLength
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
            val x = ByteBuffer.wrap(input).long
            require(x in 0..domain) { "Plaintext must be in range 0..$domain, was $x" }

            var cipher = f(0, 0)

            for (i in 1..d) {
                val xI = (x shr d - i and 1).toInt()
                cipher += (2 * xI - 1).toBigInteger() * f(i, x)
            }

            val cipherArray = cipher.toByteArray()
            System.arraycopy(cipherArray, 0, output, output.size - cipherArray.size, cipherArray.size)

        } else if (opMode == Cipher.DECRYPT_MODE) {
            val c = BigInteger(input)
            require(c >= BigInteger.ZERO && c <= n) { "Ciphertext must be in range 0..$n, was $c" }


            var a = f(0, 0)

            var x = if (c < a) 0 else 1L shl d - 1
            for (i in 2..d) {
                val xI = (x shr d - i + 1 and 1).toInt()
                a += (2 * xI - 1).toBigInteger() * f(i - 1, x)
                if (c >= a) x = x or (1L shl d - i)
            }

            val x0 = x and 1

            a += (2 * x0 - 1).toBigInteger() * f(d.toInt(), x)
            if (c != a) x = Long.MIN_VALUE // Maybe remove if Mondrian does change encrypted values

            val plaintextArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(x).array()
            System.arraycopy(plaintextArray, 0, output, 0, output.size)
        }
        return inputLen
    }

    private fun f(i: Int, x: Long): BigInteger {
        // Include only i most significant bits
        val shift = d - i
        val n = x shr shift shl shift
        return prf(n).mod(supLimitF[i] - infLimitF[i]) + infLimitF[i]
    }

    private fun prf(x: Long): BigInteger {
        val message = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(x).array()
        return BigInteger(mac.doFinal(message))
    }

}