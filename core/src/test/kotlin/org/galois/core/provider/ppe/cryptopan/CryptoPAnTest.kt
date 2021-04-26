package org.galois.core.provider.ppe.cryptopan

import org.galois.core.provider.ppe.PPETest
import org.galois.crypto.provider.ppe.cryptopan.CRYPTOPAN_ALGORITHM_NAME
import org.galois.crypto.provider.ppe.cryptopan.CryptoPAnSecretKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.RepeatedTest
import java.net.InetAddress
import java.util.*
import javax.crypto.Cipher

class CryptoPAnTest : PPETest() {

    override val algorithmName = CRYPTOPAN_ALGORITHM_NAME
    override val customKey = CryptoPAnSecretKey(ByteArray(16), ByteArray(16))
    override val base64Key =
        CryptoPAnSecretKey(Base64.getDecoder().decode("iF9aQ286q47oX8RMl9m5y/vLfwG4hw9DddOGnoADxgI="))


    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun ipV4() {
        val x = ByteArray(4)
        random.nextBytes(x)
        val address = InetAddress.getByAddress(x)

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = c.doFinal(address.address)

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted = c.doFinal(encrypted)
        assertEquals(address, InetAddress.getByAddress(decrypted))
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun ipV6() {
        val x = ByteArray(16)
        random.nextBytes(x)
        val address: InetAddress = InetAddress.getByAddress(x)

        c.init(Cipher.ENCRYPT_MODE, key)
        val encrypted: ByteArray = c.doFinal(address.address)

        c.init(Cipher.DECRYPT_MODE, key)
        val decrypted: ByteArray = c.doFinal(encrypted)
        assertEquals(address, InetAddress.getByAddress(decrypted))
    }
}