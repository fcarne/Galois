package org.galois.core.provider.fpe.ff3

import org.galois.core.provider.fpe.FPETest
import java.util.*

class FF3Test : FPETest() {
    override val parameterSpec: FF3ParameterSpec get() = FF3ParameterSpec(radix = 16, tweak = ByteArray(8))

    override val algorithmName = FF3_ALGORITHM_NAME
    override val customKey = FF3SecretKey(ByteArray(16))
    override val base64Key = FF3SecretKey(Base64.getDecoder().decode("H1PJDWZ8A5ItaGkZOrBiBg=="))
}