package org.galois.core.provider.ope.piore

import org.galois.core.provider.ope.OPETest
import org.galois.crypto.provider.ope.piore.PIORESecretKey
import crypto.provider.ope.piore.PIORE_ALGORITHM_NAME
import java.util.*

class PIORETest : OPETest() {
    override val algorithmName = PIORE_ALGORITHM_NAME
    override val customKey = PIORESecretKey(16.toByte(), 8.toByte(), ByteArray(30))
    override val base64Key = PIORESecretKey(Base64.getDecoder().decode("JTbfxrghvc2TDIR6/Bp/yGugI5kD2F8xMB3PLZ/iEwg="))
}