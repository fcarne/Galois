package org.galois.crypto.provider.fpe.ff3

import crypto.provider.GaloisCipher
import crypto.provider.toHexString
import java.math.BigInteger
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor
import kotlin.math.ceil

const val FF3_ALGORITHM_NAME = "FF3"

class FF3Cipher : GaloisCipher() {
    private lateinit var parameterSpec: FF3ParameterSpec

    private lateinit var cipherKey: SecretKeySpec

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val ff3SecretKey = FF3SecretKey(keyBytes)

        cipherKey = SecretKeySpec(ff3SecretKey.encoded.reversedArray(), FF3SecretKey.CIPHER_KEY_ALGORITHM)
    }

    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec,
        secureRandom: SecureRandom
    ) {
        parameterSpec = if (algorithmParameterSpec is FF3ParameterSpec) algorithmParameterSpec
        else throw InvalidAlgorithmParameterException("algorithmParameterSpec must be of type ${FF3ParameterSpec::class.java.name}")

        engineInit(opMode, key, secureRandom)
    }

    override fun engineGetIV() = parameterSpec.tweak

    override fun engineGetOutputSize(inputLen: Int) = inputLen

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        if (!this::parameterSpec.isInitialized) parameterSpec = FF3ParameterSpec()

        val radix: Int
        val tweak: ByteArray
        with(parameterSpec) {
            if (this.tweak == null)
                if (opMode == Cipher.ENCRYPT_MODE) generateRandomTweak()
                else throw IllegalArgumentException("Tweak must be explicitly initialized in DECRYPT_MODE")

            radix = this.radix
            tweak = this.tweak!!

            require(inputLen in minLen..maxLen)
            { "Message length $inputLen is not within min $minLen and max $maxLen bounds" }
        }

        val cipher = Cipher.getInstance(FF3SecretKey.CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey)

        val inputString = String(input)
        try {
            BigInteger(inputString, radix)
        } catch (e: NumberFormatException) {
            throw InvalidParameterException("The input is not supported in the current radix $radix")
        }

        // Calculate split point
        val u = ceil(inputLen / 2.0).toInt()
        val v = inputLen - u

        // Split the message
        var a = inputString.substring(0, u)
        var b = inputString.substring(u)

        // Split the tweak
        val tL: ByteArray = tweak.copyOfRange(0, 4)
        val tR: ByteArray = tweak.copyOfRange(4, 8)

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        val radixPowU = radix.toBigInteger().pow(u)
        val radixPowV = radix.toBigInteger().pow(v)

        if (opMode == Cipher.ENCRYPT_MODE) {
            for (i in 0..7) {
                // Determine alternating Feistel round side, right or left
                val m: Int
                val w: ByteArray
                val radixPowM: BigInteger

                if (i % 2 == 0) {
                    m = u
                    w = tR
                    radixPowM = radixPowU
                } else {
                    m = v
                    w = tL
                    radixPowM = radixPowV
                }

                // P is fixed-length 16 bytes
                val p = calculateP(i, radix, w, b).reversedArray()
                val s: ByteArray = cipher.doFinal(p).reversedArray()
                val y = BigInteger(s.toHexString(), 16)

                // Calculate c
                val cBig = try {
                    BigInteger(a.reversed(), radix)
                } catch (ex: NumberFormatException) {
                    throw RuntimeException("string a is not within base/radix")
                }.add(y).mod(radixPowM)

                // Convert c to sting using radix and length m
                var c = cBig.toString(radix).reversed()
                c += "0".repeat(m - c.length)

                // Final steps
                a = b
                b = c
            }
        } else if (opMode == Cipher.DECRYPT_MODE) {
            for (i in 7 downTo 0) {
                // Determine alternating Feistel round side, right or left
                val m: Int
                val w: ByteArray
                val radixPowM: BigInteger

                if (i % 2 == 0) {
                    m = u
                    w = tR
                    radixPowM = radixPowU
                } else {
                    m = v
                    w = tL
                    radixPowM = radixPowV
                }

                // P is fixed-length 16 bytes
                val p = calculateP(i, radix, w, a).reversedArray()
                val s: ByteArray = cipher.doFinal(p).reversedArray()
                val y = BigInteger(s.toHexString(), 16)

                // Calculate c
                val cBig = try {
                    BigInteger(b.reversed(), radix)
                } catch (ex: NumberFormatException) {
                    throw RuntimeException("string a is not within base/radix")
                }.subtract(y).mod(radixPowM)

                // Convert c to sting using radix and length m
                var c = cBig.toString(radix).reversed()
                c += "0".repeat(m - c.length)

                // Final steps
                b = a
                a = c
            }
        }

        val resultArray = (a + b).toByteArray()
        System.arraycopy(resultArray, 0, output, 0, resultArray.size)

        return inputLen
    }

    private fun calculateP(i: Int, radix: Int, w: ByteArray, s: String): ByteArray {
        val p = ByteArray(16) // P is always 16 bytes, zero initialized
        w.copyInto(p, 0, 0, 3)
        p[3] = (w[3] xor i.toByte())
        // The remaining 12 bytes of P are copied from reverse(B) with padding
        val sBytes = BigInteger(s.reversed(), radix).toByteArray()
        System.arraycopy(sBytes, 0, p, 16 - sBytes.size, sBytes.size)

        return p
    }

}
