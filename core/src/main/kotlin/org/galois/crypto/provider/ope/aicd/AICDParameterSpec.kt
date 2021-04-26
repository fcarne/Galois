package org.galois.crypto.provider.ope.aicd

import org.galois.crypto.provider.description.ParameterDescription
import org.galois.crypto.provider.ope.aicd.AICDSecretKey
import java.security.spec.AlgorithmParameterSpec
import kotlin.math.ceil
import kotlin.math.log2

class AICDParameterSpec(m: Long = 256) : AlgorithmParameterSpec {
    @ParameterDescription(
        "The upper limit of the input domain",
        ParameterDescription.ConditionType.LOWER_LIMIT,
        "0"
    )
    var m: Long = 256
        set(value) {
            require(value > 1) { "M must be in positive, was $value" }
            field = value
        }

    val minKeySize: Int
        get() {
            val minLambda = 8.0 / 3 * log2(m.toDouble())

            return if (minLambda + 2 < AICDSecretKey.KEY_SIZES[0]) AICDSecretKey.KEY_SIZES[0]
            else ceil(minLambda).toInt()
        }

    init {
        this.m = m
    }


}

