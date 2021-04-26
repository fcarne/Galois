package crypto.provider

import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.CipherSpi
import javax.crypto.NoSuchPaddingException
import kotlin.experimental.xor

abstract class GaloisCipher : CipherSpi() {
    protected var opMode = 0

    @Throws(NoSuchAlgorithmException::class)
    override fun engineSetMode(mode: String) = throw NoSuchAlgorithmException("Cipher mode: $mode not found")

    @Throws(NoSuchPaddingException::class)
    override fun engineSetPadding(padding: String) = throw NoSuchPaddingException("Padding: $padding not implemented")

    @Throws(InvalidKeyException::class)
    abstract override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom)

    @Throws(InvalidKeyException::class, InvalidAlgorithmParameterException::class)
    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec,
        secureRandom: SecureRandom
    ) {
        engineInit(opMode, key, secureRandom)
    }

    @Throws(InvalidKeyException::class)
    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameters: AlgorithmParameters,
        secureRandom: SecureRandom
    ) {
        engineInit(opMode, key, secureRandom)
    }

    abstract override fun engineGetOutputSize(inputLen: Int): Int

    override fun engineGetBlockSize(): Int = 1

    override fun engineGetIV(): ByteArray? = null

    override fun engineGetParameters(): AlgorithmParameters? = null

    override fun engineUpdate(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray {
        val output = ByteArray(engineGetOutputSize(inputLen))
        engineUpdate(input, inputOffset, inputLen, output, 0)
        return output
    }

    abstract override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int

    override fun engineDoFinal(input: ByteArray, inputOffset: Int, inputLen: Int): ByteArray =
        engineUpdate(input, inputOffset, inputLen)

    override fun engineDoFinal(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int = engineUpdate(input, inputOffset, inputLen, output, outputOffset)

    @Throws(InvalidKeyException::class)
    protected fun getKeyBytes(key: Key?): ByteArray {
        if (key == null) throw InvalidKeyException("No key given")
        if (!"RAW".equals(key.format, ignoreCase = true))
            throw InvalidKeyException("Wrong format: RAW bytes needed")

        return key.encoded ?: throw InvalidKeyException("RAW key bytes missing")
    }
}

fun String.decodeHex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

fun ByteArray.xor(other: ByteArray): ByteArray {
    val result = this.clone()
    for (i in result.indices) result[i] = result[i] xor other[i]
    return result
}