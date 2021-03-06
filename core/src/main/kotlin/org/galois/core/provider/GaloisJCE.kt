package org.galois.core.provider

import org.galois.core.provider.description.AlgorithmDescription
import org.galois.core.provider.description.ParameterDescription
import org.galois.core.provider.fpe.dff.*
import org.galois.core.provider.fpe.ff3.*
import org.galois.core.provider.ope.acope.*
import org.galois.core.provider.ope.aicd.*
import org.galois.core.provider.ope.fope.*
import org.galois.core.provider.ope.pore.*
import org.galois.core.provider.ppe.cryptopan.*
import org.galois.core.provider.ppe.hpcbc.*
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import kotlin.reflect.KClass
import kotlin.reflect.full.findAnnotation
import kotlin.reflect.full.hasAnnotation
import kotlin.reflect.full.memberProperties
import kotlin.reflect.full.primaryConstructor

object GaloisJCE : Provider(
    "GaloisJCE",
    "2.0",
    "Galois Provider (implements FastOPE, CommonDivisor, POre, Arithmetic coding, " +
            "Crypto-PAN - Stott's extension, ESAE HPCBC+, NIST FF3, FF2 addendum DFF, AES ECB Mode and Blowfish ECB Mode)"
) {
    val random = SecureRandom()

    val opeAlgorithms = listOf(AICD_ALGORITHM_NAME, FOPE_ALGORITHM_NAME, PORE_ALGORITHM_NAME)
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

        // PORE
        put("Cipher.$PORE_ALGORITHM_NAME", PORECipher::class.java.canonicalName)
        put("KeyGenerator.$PORE_ALGORITHM_NAME", POREKeyGenerator::class.java.canonicalName)

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
        val family = when (algorithm) {
            in opeAlgorithms -> "OPE"
            in fpeAlgorithms -> "FPE"
            in ppeAlgorithms -> "PPE"
            else -> "SYM"
        }
        val description = AlgorithmDescription(algorithm, family)
        val parameterClass: KClass<*>? = when (algorithm) {
            AICD_ALGORITHM_NAME -> {
                description.keySizes = AICDSecretKey.KEY_SIZES
                AICDParameterSpec::class
            }
            FOPE_ALGORITHM_NAME -> {
                description.keySizes = FOPESecretKey.KEY_SIZES
                FOPEParameterSpec::class
            }
            PORE_ALGORITHM_NAME -> {
                description.keySizes = PORESecretKey.KEY_SIZES
                POREParameterSpec::class
            }
            ACOPE_ALGORITHM_NAME -> {
                description.keySizes = ACOPESecretKey.KEY_SIZES
                ACOPEParameterSpec::class
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

        description.parameters = parameterClass?.memberProperties?.filter { param -> param.hasAnnotation<ParameterDescription>() }?.map { param ->
                val annotation = param.findAnnotation<ParameterDescription>()!!
                AlgorithmDescription.Parameter(
                    param.name,
                    annotation.description,
                    annotation.conditionType,
                    annotation.condition,
                    annotation.decryptionRequired
                )
            }?.toMutableList()

        if (algorithm in ppeAlgorithms) {
            description.parameters?.add(
                AlgorithmDescription.Parameter(
                    "ip",
                    "The ip version (if the input represents ip-addresses)",
                    ParameterDescription.ConditionType.DISTINCT_VALUES,
                    "4, 6",
                    false
                )
            )
            description.parameters?.add(
                AlgorithmDescription.Parameter(
                    "suffix",
                    "If the input should preserve the suffix instead of the prefix",
                    ParameterDescription.ConditionType.BOOLEAN,
                    "",
                    false
                )
            )
        }

        return description
    }

    fun getDescription() = supportedAlgorithms.sorted().map { getDescription(it) }

}