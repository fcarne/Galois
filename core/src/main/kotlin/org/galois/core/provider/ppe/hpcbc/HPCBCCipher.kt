package org.galois.core.provider.ppe.hpcbc

import org.galois.core.provider.GaloisCipher
import org.galois.core.provider.decodeHex
import org.galois.core.provider.toHexString
import org.galois.core.provider.xor
import org.galois.core.provider.fpe.ff3.FF3ParameterSpec
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

const val HPCBC_ALGORITHM_NAME = "HPCBC"

class HPCBCCipher : GaloisCipher() {
    private var parameterSpec = HPCBCParameterSpec()
    private lateinit var cipherKey: SecretKey
    private lateinit var cipherSpec: FF3ParameterSpec
    private lateinit var integrityKey: SecretKey
    private lateinit var integritySpec: FF3ParameterSpec
    private lateinit var rh2Hash: RH2Hash

    override fun engineGetBlockSize() = parameterSpec.blockSize

    override fun engineGetOutputSize(inputLen: Int) = when {
        !parameterSpec.integrityCheck -> inputLen
        opMode == Cipher.ENCRYPT_MODE -> inputLen + parameterSpec.blockSize
        opMode == Cipher.DECRYPT_MODE -> {
            val outputLength: Int = inputLen - parameterSpec.blockSize
            require(outputLength >= 0) { "The ciphertext must be longer than the block size" }

            outputLength
        }
        else -> 0
    }

    @Throws(InvalidKeyException::class)
    override fun engineInit(opMode: Int, key: Key, secureRandom: SecureRandom) {
        this.opMode = opMode

        val keyBytes: ByteArray = getKeyBytes(key)
        val hpcbcSecretKey = HPCBCSecretKey(keyBytes, parameterSpec.integrityCheck)

        cipherKey = SecretKeySpec(hpcbcSecretKey.cipherKey, HPCBCSecretKey.CIPHER_ALGORITHM)
        cipherSpec = FF3ParameterSpec(16, hpcbcSecretKey.cipherTweak)

        if (parameterSpec.integrityCheck) {
            integrityKey = SecretKeySpec(hpcbcSecretKey.integrityKey, HPCBCSecretKey.CIPHER_ALGORITHM)
            integritySpec = FF3ParameterSpec(16, hpcbcSecretKey.integrityTweak)
        }

        rh2Hash = RH2Hash(hpcbcSecretKey.hashKey, parameterSpec.blockSize)
    }

    @Throws(InvalidKeyException::class, InvalidAlgorithmParameterException::class)
    override fun engineInit(
        opMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec,
        secureRandom: SecureRandom
    ) {
        parameterSpec = if (algorithmParameterSpec is HPCBCParameterSpec) algorithmParameterSpec
        else throw InvalidAlgorithmParameterException("ParameterSpec must be of type ${HPCBCParameterSpec::class.java.name}")

        engineInit(opMode, key, secureRandom)
    }

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int
    ): Int {
        val blockSize = parameterSpec.blockSize

        var cI = ByteArray(blockSize)
        var mI = ByteArray(blockSize)
        var r: ByteArray

        if (opMode == Cipher.ENCRYPT_MODE) {
            val l = parameterSpec.ceilBlocksNumber(inputLen)

            val plaintext = ByteBuffer.allocate(l * blockSize).put(input).position(0)
            var ciphertext = ByteArray(0)

            val cipher = Cipher.getInstance(HPCBCSecretKey.CIPHER_ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey, cipherSpec)

            for (i in 1..l) {
                r = mI + cI
                val hash = rh2Hash.digest(r)

                plaintext[mI]
                var p: ByteArray = hash.xor(mI)

                // last block takes only the remaining bytes (no padding)
                if (i == l && inputLen < plaintext.capacity()) {
                    val added = plaintext.capacity() - inputLen
                    p = p.sliceArray(0 until blockSize - added)
                }

                val cipherIn = p.toHexString().toByteArray()
                val cipherOut = String(cipher.doFinal(cipherIn)).decodeHex()

                cI = cipherOut.xor(hash)
                ciphertext += cI

            }

            System.arraycopy(ciphertext, 0, output, 0, inputLen)

            if (parameterSpec.integrityCheck) {
                cipher.init(Cipher.ENCRYPT_MODE, integrityKey, integritySpec)

                if (cI.size < blockSize) cI += ByteArray(blockSize - cI.size)
                r = mI + cI

                val hash = rh2Hash.digest(r)
                val p: ByteArray = hash

                val cipherIn = p.toHexString().toByteArray()
                val cipherOut = String(cipher.doFinal(cipherIn)).decodeHex()

                cI = cipherOut.xor(hash)
                System.arraycopy(cI, 0, output, inputLen, blockSize) // adds integrity block
            }

        } else if (opMode == Cipher.DECRYPT_MODE) {
            val cipherTextBlocks = if (parameterSpec.integrityCheck) inputLen - blockSize else inputLen
            val l = parameterSpec.ceilBlocksNumber(cipherTextBlocks)

            val ciphertext = ByteBuffer.allocate(l * blockSize)
                .put(input.copyOf(cipherTextBlocks)).position(0)

            var plaintext = ByteArray(0)

            val cipher = Cipher.getInstance(HPCBCSecretKey.CIPHER_ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherSpec)

            for (i in 1..l) {
                r = mI + cI
                val hash = rh2Hash.digest(r)

                ciphertext[cI]
                var q: ByteArray = cI.xor(hash)

                // last block takes only the remaining bytes (no padding)
                if (i == l && cipherTextBlocks < ciphertext.capacity()) {
                    val added = ciphertext.capacity() - cipherTextBlocks
                    q = q.sliceArray(0 until blockSize - added)
                }


                val cipherIn = q.toHexString().toByteArray()
                val cipherOut = String(cipher.doFinal(cipherIn)).decodeHex()

                mI = cipherOut.xor(hash)
                plaintext += mI
            }

            if (parameterSpec.integrityCheck) {
                val integrityBlock = input.copyOfRange(cipherTextBlocks, cipherTextBlocks + blockSize)

                cipher.init(Cipher.DECRYPT_MODE, integrityKey, integritySpec)

                if (mI.size < blockSize) mI += ByteArray(blockSize - mI.size)

                r = mI + cI
                val hash = rh2Hash.digest(r)
                val q: ByteArray = integrityBlock.xor(hash)

                val cipherIn = q.toHexString().toByteArray()
                val cipherOut = String(cipher.doFinal(cipherIn)).decodeHex()

                mI = cipherOut.xor(hash)

                if (!mI.contentEquals(ByteArray(blockSize))) plaintext = ByteArray(output.size)
            }

            System.arraycopy(plaintext, 0, output, 0, output.size)

        }

        return inputLen
    }
}