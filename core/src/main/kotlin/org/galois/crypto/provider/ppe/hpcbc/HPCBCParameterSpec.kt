package org.galois.crypto.provider.ppe.hpcbc

import org.galois.crypto.provider.description.ParameterDescription
import java.security.spec.AlgorithmParameterSpec

class HPCBCParameterSpec(blockSize: Int = 1, var integrityCheck: Boolean = false) : AlgorithmParameterSpec {

    @ParameterDescription(
        "The size of the blocks in which input strings will be divided",
        ParameterDescription.ConditionType.LOWER_LIMIT,
        "1"
    )
    var blockSize = 1
        set(value) {
            require(value > 0) { "Blocks must be at least 1 byte, was $value" }
            field = value
        }

    fun ceilBlocksNumber(n: Int) = (n + blockSize - 1) / blockSize

    init {
        this.blockSize = blockSize
    }
}