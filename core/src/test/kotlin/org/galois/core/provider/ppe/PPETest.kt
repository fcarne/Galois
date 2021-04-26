package org.galois.core.provider.ppe

import org.galois.core.provider.GaloisTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.RepeatedTest
import javax.crypto.Cipher

abstract class PPETest : GaloisTest() {
    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    override fun decryptedEqualsOriginal() {
        val x = ByteArray(16)
        random.nextBytes(x)

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = c.doFinal(x)

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted: ByteArray = c.doFinal(encrypted)
        assertArrayEquals(x, decrypted)
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    open fun encryptedPrefixRespectsOriginal() {
        val prefix = ByteArray(random.nextInt(16))
        random.nextBytes(prefix)

        val x1 = ByteArray(16)
        random.nextBytes(x1)
        System.arraycopy(prefix, 0, x1, 0, prefix.size)
        val x2 = ByteArray(16)
        random.nextBytes(x2)
        System.arraycopy(prefix, 0, x2, 0, prefix.size)

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted1: ByteArray = c.doFinal(x1)
        val encrypted2: ByteArray = c.doFinal(x2)

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted1: ByteArray = c.doFinal(encrypted1)
        val decrypted2: ByteArray = c.doFinal(encrypted2)

        assertAll(
            { assertArrayEquals(x1, decrypted1) },
            { assertArrayEquals(x2, decrypted2) },
            {
                for (i in prefix.indices) assertEquals(encrypted1[i], encrypted2[i])
                for (i in prefix.size until 16)
                    if (x1.sliceArray(prefix.size..i) contentEquals x2.sliceArray(prefix.size..i))
                        assertEquals(encrypted1[i], encrypted2[i])
                    else assertNotEquals(encrypted1.sliceArray(prefix.size..i), encrypted2.sliceArray(prefix.size..i))
            })
    }
}