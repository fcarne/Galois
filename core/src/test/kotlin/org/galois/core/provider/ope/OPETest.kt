package org.galois.core.provider.ope

import org.galois.core.provider.GaloisTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.RepeatedTest
import java.math.BigInteger
import java.nio.ByteBuffer
import javax.crypto.Cipher

abstract class OPETest : GaloisTest() {

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    override fun decryptedEqualsOriginal() {
        val x: Long = random.nextInt(255).toLong()

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = c.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(x).array())
        c.init(Cipher.DECRYPT_MODE, key)

        val decrypted: ByteArray = c.doFinal(encrypted)
        assertEquals(x, ByteBuffer.wrap(decrypted).long)
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    open fun encryptedOrderRespectsOriginal() {
        val x1: Long = random.nextInt(255).toLong()
        val x2: Long = random.nextInt(255).toLong()

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted1: ByteArray = c.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(x1).array())
        val encrypted2: ByteArray = c.doFinal(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(x2).array())

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted1: ByteArray = c.doFinal(encrypted1)
        val decrypted2: ByteArray = c.doFinal(encrypted2)

        assertAll(
            { assertEquals(x1, ByteBuffer.wrap(decrypted1).long) },
            { assertEquals(x2, ByteBuffer.wrap(decrypted2).long) },
            {
                val i: Int = BigInteger(encrypted1).compareTo(BigInteger(encrypted2))
                when {
                    x1 < x2 -> assertTrue(i < 0)
                    x1 > x2 -> assertTrue(i > 0)
                    else -> assertEquals(i, 0)
                }
            })
    }
}