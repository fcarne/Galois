package org.galois.core.provider.ppe.cryptopan

import org.galois.core.provider.GaloisCipher
import org.galois.core.provider.util.FluentBitSet
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.Key
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

const val CRYPTOPAN_ALGORITHM_NAME = "CryptoPAn"

class CryptoPANCipher : GaloisCipher() {
    private lateinit var parameterSpec: CryptoPAnParameterSpec

    private lateinit var cipher: Cipher
    private lateinit var padBits: BitSet
    private lateinit var shiftedPad: Array<BitSet?>

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val stottSecretKey = CryptoPAnSecretKey(keyBytes)

        val cipherKey = SecretKeySpec(stottSecretKey.cipherKey, CryptoPAnSecretKey.CIPHER_ALGORITHM)
        cipher = Cipher.getInstance(CryptoPAnSecretKey.CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey)

        val random = SecureRandom.getInstance("SHA1PRNG")
        random.setSeed(stottSecretKey.padSeed)

        if (!this::parameterSpec.isInitialized) parameterSpec = CryptoPAnParameterSpec()

        val padBytes = ByteArray(parameterSpec.maxLength)
        random.nextBytes(padBytes)

        val pad = Arrays.copyOfRange(cipher.doFinal(padBytes), 0, parameterSpec.maxLength)
        padBits = BitSet.valueOf(pad)

        shiftedPad = arrayOfNulls(parameterSpec.bitsMaxLength)

    }

    override fun engineGetOutputSize(inputLen: Int): Int = inputLen

    @Throws(InvalidKeyException::class, InvalidAlgorithmParameterException::class)
    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec,
        secureRandom: SecureRandom
    ) {
        parameterSpec = if (algorithmParameterSpec is CryptoPAnParameterSpec) algorithmParameterSpec
        else throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${CryptoPAnParameterSpec::class.java.name}")
        engineInit(opMode, key, secureRandom)
    }

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        require(inputLen <= parameterSpec.maxLength)
        { "Message length must be less than ${parameterSpec.maxLength}, was $inputLen" }

        val buffer = ByteBuffer.allocate(parameterSpec.maxLength).put(input).position(0)

        val plaintext: FluentBitSet = FluentBitSet.valueOf(buffer)
        var resultArray = ByteArray(0)

        val bitsLength = parameterSpec.bitsMaxLength
        if (opMode == Cipher.ENCRYPT_MODE) {
            val ciphertext = FluentBitSet(bitsLength)
            for (pos in 0 until inputLen * 8) {
                val otp = calculateOTP(plaintext, padBits, pos)
                val cipherInput = otp.toByteArray()

                val cipherOutput = cipher.doFinal(cipherInput)
                // LITTLE_ENDIAN needed because padding is added even if input is 16 bytes, making cipherText all 0s or all 1s
                val msb: FluentBitSet = FluentBitSet.valueOf(cipherOutput, ByteOrder.LITTLE_ENDIAN)[bitsLength - 1]
                ciphertext.or(msb.shr(pos))
            }
            ciphertext.xor(plaintext)
            resultArray = ciphertext.toByteArray()

        } else if (opMode == Cipher.DECRYPT_MODE) {
            for (pos in 0 until inputLen * 8) {
                val otp = calculateOTP(plaintext, padBits, pos)
                val cipherInput = otp.toByteArray()
                val cipherOutput = cipher.doFinal(cipherInput)

                val msb: FluentBitSet = FluentBitSet.valueOf(cipherOutput, ByteOrder.LITTLE_ENDIAN)[bitsLength - 1]
                plaintext.xor(msb.shr(pos))
            }
            resultArray = plaintext.toByteArray()
        }

        // if the first bytes are 0, those will be deleted. We need to know the length of the returned byte array
        // and copy it shifting by the difference
        val offset = if (resultArray.isEmpty()) inputLen
        else parameterSpec.maxLength - resultArray.size

        System.arraycopy(resultArray, 0, output, offset, inputLen - offset)

        return inputLen
    }

    private fun calculateOTP(plaintext: FluentBitSet, padBits: BitSet, pos: Int): FluentBitSet {
        val length = parameterSpec.bitsMaxLength

        val mask = FluentBitSet(length).set(length - pos, length)
        val otp: FluentBitSet

        if (shiftedPad[pos] != null) {
            otp = FluentBitSet.valueOf(shiftedPad[pos]!!)
        } else {
            otp = FluentBitSet.valueOf(padBits).shl(pos, length)
                .or(FluentBitSet.valueOf(padBits).shr(length - pos))
            shiftedPad[pos] = otp.bitset.clone() as BitSet
        }
        otp.xor(mask.and(plaintext))
        return otp
    }

}