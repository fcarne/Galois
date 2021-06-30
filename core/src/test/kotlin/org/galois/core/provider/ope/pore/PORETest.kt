package org.galois.core.provider.ope.pore

import org.galois.core.provider.ope.OPETest
import java.util.*

class PORETest : OPETest() {
    override val algorithmName = PORE_ALGORITHM_NAME
    override val customKey = PORESecretKey(1024, 8.toByte(), ByteArray(29))
    override val base64Key = PORESecretKey(Base64.getDecoder().decode("LxcIJC9eVOf4g8aO4z7EDA=="))
}