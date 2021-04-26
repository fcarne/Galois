package org.galois.core.provider.ope.aicd

import org.galois.core.provider.ope.OPETest
import org.galois.crypto.provider.ope.aicd.AICDSecretKey
import org.galois.crypto.provider.ope.aicd.AICD_ALGORITHM_NAME
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.RepeatedTest
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.*
import javax.crypto.Cipher

class AICDTest : OPETest() {

    override val algorithmName = AICD_ALGORITHM_NAME

    override val customKey = AICDSecretKey(BigInteger("88506266647602766350238521397384533217"))

    override val base64Key = AICDSecretKey(Base64.getDecoder().decode("SwffGYVKIPZyr/HfJz7Atg=="))

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    override fun encryptedOrderRespectsOriginal() {
        val x1 = random.nextInt(255).toLong()
        val x2 = random.nextInt(255).toLong()

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted1: ByteArray = c.doFinal(ByteBuffer.allocate(java.lang.Long.BYTES).putLong(x1).array())
        val encrypted2: ByteArray = c.doFinal(ByteBuffer.allocate(java.lang.Long.BYTES).putLong(x2).array())
        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted1: ByteArray = c.doFinal(encrypted1)
        val decrypted2: ByteArray = c.doFinal(encrypted2)

        Assertions.assertAll(
            { Assertions.assertEquals(x1, ByteBuffer.wrap(decrypted1).long) },
            { Assertions.assertEquals(x2, ByteBuffer.wrap(decrypted2).long) },
            {
                val i: Int = BigInteger(encrypted1).compareTo(BigInteger(encrypted2))
                when {
                    x1 < x2 -> Assertions.assertTrue(i < 0)
                    x1 > x2 -> Assertions.assertTrue(i > 0)
                    else -> Assertions.assertNotEquals(i, 0)
                }
            })
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun sameValueDifferentCiphertexts() {
        val x = random.nextInt(255).toLong()

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted1: ByteArray = c.doFinal(ByteBuffer.allocate(java.lang.Long.BYTES).putLong(x).array())
        val encrypted2: ByteArray = c.doFinal(ByteBuffer.allocate(java.lang.Long.BYTES).putLong(x).array())
        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted1: ByteArray = c.doFinal(encrypted1)
        val decrypted2: ByteArray = c.doFinal(encrypted2)
        Assertions.assertAll(
            { Assertions.assertEquals(x, ByteBuffer.wrap(decrypted1).long) },
            { Assertions.assertEquals(x, ByteBuffer.wrap(decrypted2).long) },
            { Assertions.assertNotEquals(BigInteger(encrypted1), BigInteger(encrypted2)) })
    }
}