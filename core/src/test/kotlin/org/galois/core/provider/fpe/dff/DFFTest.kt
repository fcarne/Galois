package org.galois.core.provider.fpe.dff

import org.galois.core.provider.fpe.FPETest
import java.util.*

class DFFTest : FPETest() {
    override val parameterSpec: DFFParameterSpec get() = DFFParameterSpec(radix = 16, tweak = ByteArray(8))

    override val algorithmName = DFF_ALGORITHM_NAME
    override val customKey = DFFSecretKey(ByteArray(16))
    override val base64Key = DFFSecretKey(Base64.getDecoder().decode("H1PJDWZ8A5ItaGkZOrBiBg=="))
}