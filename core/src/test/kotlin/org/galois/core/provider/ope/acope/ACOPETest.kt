package org.galois.core.provider.ope.acope

import org.galois.core.provider.ope.OPETest
import java.util.*

class ACOPETest : OPETest() {
    override val algorithmName = ACOPE_ALGORITHM_NAME
    override val customKey = ACOPESecretKey(Array(15) { Pair(10, 10) }, 8, 15)
    override val base64Key = ACOPESecretKey(Base64.getDecoder().decode("b3hBIWo1GmN7XgxYZjp0PVEpAWxicjwIYFA4LFY4CI4="))
}