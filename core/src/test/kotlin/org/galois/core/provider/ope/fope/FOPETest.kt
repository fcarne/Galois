package org.galois.core.provider.ope.fope

import org.galois.core.provider.ope.OPETest
import java.util.*
import kotlin.math.ceil
import kotlin.math.pow

class FOPETest : OPETest() {
    override val algorithmName = FOPE_ALGORITHM_NAME
    override val customKey = FOPESecretKey(ceil(16 / (0.75 * 0.25.pow(8.0))), 0.25, 0.25, 8.toByte(), ByteArray(7))
    override val base64Key = FOPESecretKey(Base64.getDecoder().decode("Qna1nFfLZow/tQZwVvInlD+l5DzCL5LwCEe4R+UhAhQ="))
}