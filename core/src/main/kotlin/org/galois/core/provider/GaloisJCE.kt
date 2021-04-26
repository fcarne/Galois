package org.galois.core.provider

import org.galois.core.provider.ope.piore.PIORECipher
import org.galois.core.provider.ope.piore.PIOREKeyGenerator
import org.galois.core.provider.ope.piore.PIORE_ALGORITHM_NAME
import org.galois.core.provider.description.AlgorithmDescription
import org.galois.core.provider.description.ParameterDescription
import org.galois.core.provider.fpe.dff.*
import org.galois.core.provider.fpe.ff3.*
import org.galois.core.provider.ope.aicd.*
import org.galois.core.provider.ope.fope.*
import org.galois.core.provider.ope.piore.PIOREParameterSpec
import org.galois.core.provider.ope.piore.PIORESecretKey
import org.galois.core.provider.ppe.cryptopan.*
import org.galois.core.provider.ppe.hpcbc.*
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import kotlin.reflect.KClass
import kotlin.reflect.full.findAnnotation
import kotlin.reflect.full.hasAnnotation
import kotlin.reflect.full.memberProperties

object GaloisJCE : Provider(
    "GaloisJCE",
    "2.0",
    "Galois Provider (implements FastOPE, PIOre,  CommonDivisor, TYM, " +
            "Crypto-PAN - Lucent's extension, ESAE HPCBC+, NIST FF3, FF2 addendum DFF, AES ECB Mode and Blowfish ECB Mode)"
) {
    val random = SecureRandom()

    val opeAlgorithms = listOf(AICD_ALGORITHM_NAME, FOPE_ALGORITHM_NAME, PIORE_ALGORITHM_NAME)
    val ppeAlgorithms = listOf(CRYPTOPAN_ALGORITHM_NAME, HPCBC_ALGORITHM_NAME)
    val fpeAlgorithms = listOf(DFF_ALGORITHM_NAME, FF3_ALGORITHM_NAME)
    val symmetricAlgorithms = listOf("AES", "Blowfish")
    val supportedAlgorithms = opeAlgorithms + ppeAlgorithms + fpeAlgorithms + symmetricAlgorithms

    init {
        // AICD
        put("Cipher.$AICD_ALGORITHM_NAME", AICDCipher::class.java.canonicalName)
        put("KeyGenerator.$AICD_ALGORITHM_NAME", AICDKeyGenerator::class.java.canonicalName)

        // FOPE
        put("Cipher.$FOPE_ALGORITHM_NAME", FOPECipher::class.java.canonicalName)
        put("KeyGenerator.$FOPE_ALGORITHM_NAME", FOPEKeyGenerator::class.java.canonicalName)

        // PIORE
        put("Cipher.$PIORE_ALGORITHM_NAME", PIORECipher::class.java.canonicalName)
        put("KeyGenerator.$PIORE_ALGORITHM_NAME", PIOREKeyGenerator::class.java.canonicalName)

        // CRYPTO-PAN
        put("Cipher.$CRYPTOPAN_ALGORITHM_NAME", CryptoPANCipher::class.java.canonicalName)
        put("KeyGenerator.$CRYPTOPAN_ALGORITHM_NAME", CryptoPAnKeyGenerator::class.java.canonicalName)

        // HPCBC+
        put("Cipher.$HPCBC_ALGORITHM_NAME", HPCBCCipher::class.java.canonicalName)
        put("KeyGenerator.$HPCBC_ALGORITHM_NAME", HPCBCKeyGenerator::class.java.canonicalName)

        // DFF
        put("Cipher.$DFF_ALGORITHM_NAME", DFFCipher::class.java.canonicalName)
        put("KeyGenerator.$DFF_ALGORITHM_NAME", DFFKeyGenerator::class.java.canonicalName)

        // FF3
        put("Cipher.$FF3_ALGORITHM_NAME", FF3Cipher::class.java.canonicalName)
        put("KeyGenerator.$FF3_ALGORITHM_NAME", FF3KeyGenerator::class.java.canonicalName)

    }

    fun add() = Security.addProvider(this)

    fun getDescription(algorithm: String): AlgorithmDescription {
        val description = AlgorithmDescription(algorithm)
        val parameterClass: KClass<*>? = when (algorithm) {
            AICD_ALGORITHM_NAME -> {
                description.keySizes = AICDSecretKey.KEY_SIZES
                AICDParameterSpec::class
            }
            FOPE_ALGORITHM_NAME -> {
                description.keySizes = FOPESecretKey.KEY_SIZES
                FOPEParameterSpec::class
            }
            PIORE_ALGORITHM_NAME -> {
                description.keySizes = PIORESecretKey.KEY_SIZES
                PIOREParameterSpec::class
            }
            CRYPTOPAN_ALGORITHM_NAME -> {
                description.keySizes = CryptoPAnSecretKey.KEY_SIZES
                CryptoPAnParameterSpec::class
            }
            HPCBC_ALGORITHM_NAME -> {
                description.keySizes = HPCBCSecretKey.KEY_SIZES
                HPCBCParameterSpec::class
            }
            FF3_ALGORITHM_NAME -> {
                description.keySizes = FF3SecretKey.KEY_SIZES
                FF3ParameterSpec::class
            }
            DFF_ALGORITHM_NAME -> {
                description.keySizes = DFFSecretKey.KEY_SIZES
                DFFParameterSpec::class
            }
            "AES" -> {
                description.keySizes = intArrayOf(128, 192, 256)
                null
            }
            "Blowfish" -> {
                description.keySizes = intArrayOf(128, 192, 256, 384)
                null
            }
            else -> throw IllegalArgumentException("$algorithm not yet supported")
        }

        description.parameters =
            parameterClass?.memberProperties?.filter { f -> f.hasAnnotation<ParameterDescription>() }?.map { f ->
                val annotation = f.findAnnotation<ParameterDescription>()!!
                AlgorithmDescription.Parameter(
                    f.name,
                    annotation.description,
                    annotation.conditionType,
                    annotation.condition
                )
            }?.toMutableList()

        if (algorithm in ppeAlgorithms) {
            description.parameters?.add(
                AlgorithmDescription.Parameter(
                    "ip",
                    "The ip version (if the input represents ip-addresses)",
                    ParameterDescription.ConditionType.DISTINCT_VALUES,
                    "[4, 6]"
                )
            )
            description.parameters?.add(
                AlgorithmDescription.Parameter(
                    "suffix",
                    "If the input should preserve the suffix instead of the prefix",
                    ParameterDescription.ConditionType.BOOLEAN,
                    ""
                )
            )
        }

        return description
    }

    fun getDescription() = supportedAlgorithms.sorted().map { getDescription(it) }

}