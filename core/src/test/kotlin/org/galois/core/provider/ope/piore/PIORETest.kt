package org.galois.core.provider.ope.piore

import org.galois.core.provider.ope.OPETest
import java.util.*

class PIORETest : OPETest() {
    override val algorithmName = PIORE_ALGORITHM_NAME
    override val customKey = PIORESecretKey(1000, 8.toByte(), ByteArray(29))
    override val base64Key = PIORESecretKey(Base64.getDecoder().decode("LxcIJC9eVOf4g8aO4z7EDA=="))
}