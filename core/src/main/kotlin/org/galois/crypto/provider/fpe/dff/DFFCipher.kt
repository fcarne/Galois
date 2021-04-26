package org.galois.crypto.provider.fpe.dff

import crypto.provider.GaloisCipher
import crypto.provider.toHexString
import crypto.provider.xor
import java.math.BigInteger
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

const val DFF_ALGORITHM_NAME = "DFF"

class DFFCipher : GaloisCipher() {
    private lateinit var parameterSpec: DFFParameterSpec

    private lateinit var cipherKey: SecretKeySpec

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val dffSecretKey = DFFSecretKey(keyBytes)

        cipherKey = SecretKeySpec(dffSecretKey.encoded, DFFSecretKey.CIPHER_KEY_ALGORITHM)
    }

    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec,
        secureRandom: SecureRandom
    ) {
        parameterSpec = if (algorithmParameterSpec is DFFParameterSpec) algorithmParameterSpec
        else throw InvalidAlgorithmParameterException("algorithmParameterSpec must be of type ${DFFParameterSpec::class.java.name}")

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
        if (!this::parameterSpec.isInitialized) parameterSpec = DFFParameterSpec()

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

        val inputString = String(input)
        try {
            BigInteger(inputString, radix)
        } catch (e: NumberFormatException) {
            throw InvalidParameterException("The input is not supported in the current radix $radix")
        }

        val p = calculateP(radix, inputLen, tweak)
        val t1 = ByteArray(16)
        tweak.copyInto(t1, 3)

        val cipher = Cipher.getInstance(DFFSecretKey.CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey)

        val j = cipher.doFinal(p)
        val j1 = cipher.doFinal(t1)

        // Calculate split point
        val u = inputLen / 2
        val v = inputLen - u

        // Split the message
        var a = inputString.substring(0, u)
        var b = inputString.substring(u)

        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        val radixPowU = radix.toBigInteger().pow(u)
        val radixPowV = radix.toBigInteger().pow(v)

        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(j, DFFSecretKey.CIPHER_KEY_ALGORITHM))
        if (opMode == Cipher.ENCRYPT_MODE) {
            for (i in 0..9) {
                // Determine alternating Feistel round side, right or left
                val m: Int
                val radixPowM: BigInteger

                if (i % 2 == 0) {
                    m = u
                    radixPowM = radixPowU
                } else {
                    m = v
                    radixPowM = radixPowV
                }

                val q = calculateQ(i, radix, b)
                val y = cipher.doFinal(q.xor(j1))
                val yBig = BigInteger(y.toHexString(), 16)

                // Calculate c
                val cBig = try {
                    BigInteger(a, radix)
                } catch (ex: NumberFormatException) {
                    throw RuntimeException("string a is not within base/radix")
                }.add(yBig).mod(radixPowM)

                // Convert c to sting using radix and length m
                var c = cBig.toString(radix)
                c = "0".repeat(m - c.length) + c

                // Final steps
                a = b
                b = c
            }
        } else if (opMode == Cipher.DECRYPT_MODE) {
            for (i in 9 downTo 0) {
                // Determine alternating Feistel round side, right or left
                val m: Int
                val radixPowM: BigInteger

                if (i % 2 == 0) {
                    m = u
                    radixPowM = radixPowU
                } else {
                    m = v
                    radixPowM = radixPowV
                }

                val q = calculateQ(i, radix, a)
                val y = cipher.doFinal(q.xor(j1))
                val yBig = BigInteger(y.toHexString(), 16)

                // Calculate c
                val cBig = try {
                    BigInteger(b, radix)
                } catch (ex: NumberFormatException) {
                    throw RuntimeException("string a is not within base/radix")
                }.subtract(yBig).mod(radixPowM)

                // Convert c to sting using radix and length m
                var c = cBig.toString(radix)
                c = "0".repeat(m - c.length) + c

                // Final steps
                b = a
                a = c

            }
        }

        val resultArray = (a + b).toByteArray()
        System.arraycopy(resultArray, 0, output, 0, resultArray.size)

        return inputLen
    }

    private fun calculateP(radix: Int, inputLen: Int, tweak: ByteArray): ByteArray {
        val p = ByteArray(16)
        p[0] = radix.toByte()
        p[1] = tweak.size.toByte()
        p[2] = inputLen.toByte()
        System.arraycopy(tweak, 0, p, 16 - tweak.size, tweak.size)
        return p
    }

    private fun calculateQ(i: Int, radix: Int, s: String): ByteArray {
        val q = ByteArray(16) // Q is always 16 bytes, zero initialized
        q[0] = i.toByte()
        val sBytes = BigInteger(s, radix).toByteArray()
        System.arraycopy(sBytes, 0, q, 16 - sBytes.size, sBytes.size)
        return q
    }

}