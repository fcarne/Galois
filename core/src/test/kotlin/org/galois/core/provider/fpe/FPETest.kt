package org.galois.core.provider.fpe

import algorithm.GaloisTest
import org.galois.crypto.provider.fpe.FPEParameterSpec
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.RepeatedTest
import javax.crypto.Cipher

abstract class FPETest : GaloisTest() {
    private val charPool: List<Char> = ('0'..'9') + ('a'..'z')

    abstract val parameterSpec: FPEParameterSpec

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    override fun decryptedEqualsOriginal() {
        val x = randomString()

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = c.doFinal(x.toByteArray())

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted: ByteArray = c.doFinal(encrypted)

        assertEquals(x, String(decrypted))
    }

    private fun randomString(radix: Int = 10, length: Int = 8) =
        (1..length).map { random.nextInt(radix) }.map(charPool::get).joinToString("")

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    open fun encryptedLengthAndRadixRespectOriginal() {
        val x = randomString(parameterSpec.radix, 8)

        c.init(Cipher.ENCRYPT_MODE, key, parameterSpec)
        val encrypted = c.doFinal(x.toByteArray())

        c.init(Cipher.DECRYPT_MODE, key, parameterSpec)
        val decrypted = c.doFinal(encrypted)

        assertAll(
            { assertEquals(x, String(decrypted)) },
            { assertEquals(x.length, String(decrypted).length) },
            {
                val pattern = if (parameterSpec.radix <= 10) "[0-${parameterSpec.radix - 1}]+"
                else "[0-9a-${'a' + parameterSpec.radix - 11}]+"
                assertTrue(String(encrypted).matches(Regex(pattern)))
            })
    }
}