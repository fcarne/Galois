package algorithm

import crypto.provider.GaloisJCE
import org.junit.jupiter.api.*
import javax.crypto.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class GaloisTest {
    protected abstract val algorithmName: String

    protected lateinit var key: SecretKey
    protected lateinit var c: Cipher
    protected val random = GaloisJCE.random
    protected abstract val customKey: SecretKey
    protected abstract val base64Key: SecretKey

    @BeforeAll
    fun add() {
        GaloisJCE.add()
    }

    @BeforeEach
    fun setup() {
        val keyGen = KeyGenerator.getInstance(algorithmName)
        key = keyGen.generateKey()
        c = Cipher.getInstance(algorithmName)
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    abstract fun decryptedEqualsOriginal()

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun customKey() {
        key = customKey
        decryptedEqualsOriginal()
    }

    @RepeatedTest(value = 50, name = RepeatedTest.LONG_DISPLAY_NAME)
    fun base64Key() {
        key = base64Key
        decryptedEqualsOriginal()
    }

}