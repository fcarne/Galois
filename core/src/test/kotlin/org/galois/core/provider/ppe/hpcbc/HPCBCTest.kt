package org.galois.core.provider.ppe.hpcbc

import org.galois.core.provider.ppe.PPETest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.RepeatedTest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

class HPCBCTest : PPETest() {

    override val algorithmName = HPCBC_ALGORITHM_NAME
    override val customKey = HPCBCSecretKey(ByteArray(16), ByteArray(8), ByteArray(8))
    override val base64Key =
        HPCBCSecretKey(Base64.getDecoder().decode("iF9aQ286q47oX8RMl9m5y/vLfwG4hw9DddOGnoADxgI="), false)

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun encryptedWithIntegrityCheck() {
        val parameterSpec = HPCBCParameterSpec(integrityCheck = true)
        val keyGenerator = KeyGenerator.getInstance(algorithmName)

        keyGenerator.init(parameterSpec)
        key = keyGenerator.generateKey()

        val x = ByteArray(8)
        random.nextBytes(x)


        c.init(Cipher.ENCRYPT_MODE, key, parameterSpec)
        val encrypted: ByteArray = c.doFinal(x)

        c.init(Cipher.DECRYPT_MODE, key, parameterSpec)
        val decrypted: ByteArray = c.doFinal(encrypted)
        assertArrayEquals(x, decrypted)
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    override fun encryptedPrefixRespectsOriginal() {
        val parameterSpec = HPCBCParameterSpec(blockSize = 1 + random.nextInt(4))
        val prefix = ByteArray(random.nextInt(8))
        random.nextBytes(prefix)

        val x1 = ByteArray(8)
        random.nextBytes(x1)
        System.arraycopy(prefix, 0, x1, 0, prefix.size)
        val x2 = ByteArray(8)
        random.nextBytes(x2)
        System.arraycopy(prefix, 0, x2, 0, prefix.size)

        c.init(Cipher.ENCRYPT_MODE, key, parameterSpec)
        val encrypted1: ByteArray = c.doFinal(x1)
        val encrypted2: ByteArray = c.doFinal(x2)

        c.init(Cipher.DECRYPT_MODE, key, parameterSpec)
        val decrypted1: ByteArray = c.doFinal(encrypted1)
        val decrypted2: ByteArray = c.doFinal(encrypted2)

        assertAll(
            { assertArrayEquals(x1, decrypted1) },
            { assertArrayEquals(x2, decrypted2) },
            {
                for (i in 0 until 8 / parameterSpec.blockSize) {
                    if (x1.sliceArray(0 until (i + 1) * parameterSpec.blockSize) contentEquals x2.sliceArray(0 until (i + 1) * parameterSpec.blockSize))
                        assertArrayEquals(
                            encrypted1.sliceArray(i * parameterSpec.blockSize until (i + 1) * parameterSpec.blockSize),
                            encrypted2.sliceArray(i * parameterSpec.blockSize until (i + 1) * parameterSpec.blockSize)
                        )
                    else
                        assertNotEquals(
                            encrypted1.sliceArray(0 until (i + 1) * parameterSpec.blockSize),
                            encrypted2.sliceArray(0 until (i + 1) * parameterSpec.blockSize)
                        )
                }

                // last block (if partial)
                if (x1 contentEquals x2) assertArrayEquals(encrypted1, encrypted2)
                else assertNotEquals(encrypted1, encrypted2)

            }
        )
    }
}