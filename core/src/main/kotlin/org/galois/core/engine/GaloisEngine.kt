package org.galois.core.engine

import org.galois.core.provider.decodeHex
import org.galois.core.provider.ope.piore.PIORE_ALGORITHM_NAME
import org.galois.core.provider.toHexString
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.galois.core.provider.GaloisJCE
import org.galois.core.provider.fpe.FPEParameterSpec
import org.galois.core.provider.fpe.dff.DFFParameterSpec
import org.galois.core.provider.fpe.dff.DFF_ALGORITHM_NAME
import org.galois.core.provider.fpe.ff3.FF3ParameterSpec
import org.galois.core.provider.ope.aicd.AICDParameterSpec
import org.galois.core.provider.ope.aicd.AICD_ALGORITHM_NAME
import org.galois.core.provider.ope.fope.FOPEParameterSpec
import org.galois.core.provider.ope.fope.FOPE_ALGORITHM_NAME
import org.galois.core.provider.ope.piore.PIOREParameterSpec
import org.galois.core.provider.ppe.cryptopan.CRYPTOPAN_ALGORITHM_NAME
import org.galois.core.provider.ppe.cryptopan.CryptoPAnParameterSpec
import org.galois.core.provider.ppe.hpcbc.HPCBCParameterSpec
import org.galois.core.provider.ppe.hpcbc.HPCBC_ALGORITHM_NAME
import tech.tablesaw.api.StringColumn
import tech.tablesaw.api.Table
import tech.tablesaw.columns.Column
import java.math.BigInteger
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.math.ceil
import kotlin.math.log2

class GaloisEngine(private val dataset: Table, configuration: EngineConfiguration) {
    private val configuration: EngineConfiguration

    init {
        GaloisJCE.add()
        this.configuration = configuration

        val columns = configuration.encryptionDetails.map { it.columnName }

        val nonExistentColumns = columns.minus(dataset.columnNames())
        require(nonExistentColumns.isEmpty())
        { "Columns $nonExistentColumns do not exist in the dataset" }

        val duplicateColumns = columns.groupingBy { it }.eachCount().filter { it.value > 1 }
        require(duplicateColumns.isEmpty())
        { "Each column must appear only once: ${duplicateColumns.keys} appeared more than once" }

        val ciphers = configuration.encryptionDetails.map { it.cipher }
        val notSupportedCiphers = ciphers.minus(GaloisJCE.supportedAlgorithms)
        require(notSupportedCiphers.isEmpty())
        { "Ciphers $notSupportedCiphers are not yet supported" }


        if (configuration.mode == Mode.DECRYPT) {
            val nullKeys = configuration.encryptionDetails.filter { it.key == null }
            require(nullKeys.isEmpty()) { "In DECRYPT mode all keys must be explicitly set" }

            val nullTweak = configuration.encryptionDetails.filter {
                it.cipher in GaloisJCE.fpeAlgorithms && it.params.cipherSpecific["tweak"] == null
            }
            require(nullTweak.isEmpty()) { "In DECRYPT mode, tweaks for must be explicitly set. Set them for columns ${nullTweak.map { it.columnName }}" }
        }

    }

    suspend fun compute(): Table = coroutineScope {
        val result = dataset.copy()
        val columns = configuration.encryptionDetails.map {
            async { columnDoFinal(it, dataset.column(it.columnName)) }
        }
        val computedColumns = columns.map { it.await() }
        computedColumns.forEach { result.replaceColumn(it) }

        result
    }


    private suspend fun columnDoFinal(detail: EncryptionDetail, column: Column<*>): Column<*> = coroutineScope {
        val computedColumn = StringColumn.create(column.name())
        val cipher = initCipher(detail, column)

        val computedTaxonomy = detail.params.taxonomyTree?.let { async { taxonomyTreeDoFinal(it, detail, column) } }

        column.forEach { value ->
            val cell = value.toString()

            val input = valueToByteArray(cell, detail)
            val output = cipher.doFinal(input)
            computedColumn.append(byteArrayToValue(output, detail))
        }

        computedTaxonomy?.await()

        computedColumn
    }


    private fun taxonomyTreeDoFinal(taxonomyTree: TaxonomyTree, detail: EncryptionDetail, column: Column<*>) {
        val cipher = initCipher(detail, column)
        taxonomyNodeDoFinal(taxonomyTree.tree, cipher, detail)
    }

    private fun taxonomyNodeDoFinal(node: TaxonomyNode, cipher: Cipher, detail: EncryptionDetail) {
        val input = valueToByteArray(node.cat, detail)
        val output = cipher.doFinal(input)
        node.cat = byteArrayToValue(output, detail)

        node.subcats?.forEach { subNode -> taxonomyNodeDoFinal(subNode, cipher, detail) }
    }

    private fun valueToByteArray(cell: String, detail: EncryptionDetail): ByteArray {
        val suffixMode =
            detail.cipher in GaloisJCE.ppeAlgorithms && detail.params.cipherSpecific["suffix"] == true
        val ipMode =
            detail.cipher in GaloisJCE.ppeAlgorithms && detail.params.cipherSpecific.containsKey("ip")

        val opMode = configuration.mode
        return when {
            detail.cipher in GaloisJCE.opeAlgorithms && opMode == Mode.ENCRYPT ->
                ByteBuffer.allocate(Long.SIZE_BYTES).putLong(cell.toLong()).array()
            detail.cipher in GaloisJCE.opeAlgorithms && opMode == Mode.DECRYPT ->
                BigInteger(cell).toByteArray()

            ipMode && !suffixMode -> InetAddress.getByName(cell).address
            ipMode && suffixMode -> InetAddress.getByName(cell).address.reverseBits()

            suffixMode && opMode == Mode.ENCRYPT -> cell.reversed().toByteArray()
            suffixMode && opMode == Mode.DECRYPT -> Base64.getDecoder().decode(cell.reversed())

            detail.cipher in GaloisJCE.fpeAlgorithms -> cell.toByteArray()

            ((!suffixMode && !ipMode) || detail.cipher in GaloisJCE.symmetricAlgorithms) && opMode == Mode.ENCRYPT ->
                cell.toByteArray()
            else -> Base64.getDecoder().decode(cell)
        }
    }

    private fun byteArrayToValue(byteArray: ByteArray, detail: EncryptionDetail): String {
        val suffixMode =
            detail.cipher in GaloisJCE.ppeAlgorithms && detail.params.cipherSpecific["suffix"] == true
        val ipMode =
            detail.cipher in GaloisJCE.ppeAlgorithms && detail.params.cipherSpecific.containsKey("ip")
        val opMode = configuration.mode

        return when {
            detail.cipher in GaloisJCE.opeAlgorithms && opMode == Mode.ENCRYPT ->
                BigInteger(byteArray).toString()
            detail.cipher in GaloisJCE.opeAlgorithms && opMode == Mode.DECRYPT ->
                ByteBuffer.wrap(byteArray).long.toString()

            ipMode && !suffixMode -> InetAddress.getByAddress(byteArray).hostAddress
            ipMode && suffixMode -> InetAddress.getByAddress(byteArray.reverseBits()).hostAddress

            suffixMode && opMode == Mode.ENCRYPT -> Base64.getEncoder().encodeToString(byteArray).reversed()
            suffixMode && opMode == Mode.DECRYPT -> String(byteArray).reversed()

            detail.cipher in GaloisJCE.fpeAlgorithms -> String(byteArray)

            ((!suffixMode && !ipMode) || detail.cipher in GaloisJCE.symmetricAlgorithms) && opMode == Mode.ENCRYPT ->
                Base64.getEncoder().encodeToString(byteArray)
            else -> String(byteArray)
        }
    }

    private fun initCipher(detail: EncryptionDetail, column: Column<*>): Cipher {
        val secretKey: SecretKey
        val cipher = Cipher.getInstance(detail.cipher)
        val opMode = if (configuration.mode == Mode.ENCRYPT) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE

        if (detail.key != null) {
            secretKey = SecretKeySpec(Base64.getDecoder().decode(detail.key), detail.cipher)
        } else {
            val keyGenerator = KeyGenerator.getInstance(detail.cipher)

            // if it's an opeScheme or HPCBC+ set parameters
            if (detail.cipher in GaloisJCE.opeAlgorithms + HPCBC_ALGORITHM_NAME)
                keyGenerator.init(getParameterSpec(detail, column))

            // set keySize, after the parameters since an algorithm key size may depend on these parameters
            if (detail.cipher != AICD_ALGORITHM_NAME) detail.params.keySize?.let { keyGenerator.init(it) }

            secretKey = keyGenerator.generateKey()
            detail.key = Base64.getEncoder().encodeToString(secretKey.encoded)
        }
        if (detail.cipher in GaloisJCE.opeAlgorithms + GaloisJCE.symmetricAlgorithms)
            cipher.init(opMode, secretKey)
        else
            cipher.init(opMode, secretKey, getParameterSpec(detail, column))
        return cipher
    }

    private fun getParameterSpec(detail: EncryptionDetail, column: Column<*>): AlgorithmParameterSpec? {
        return when (detail.cipher) {
            AICD_ALGORITHM_NAME -> {
                val parameterSpec = AICDParameterSpec()
                parameterSpec.m = detail.params.cipherSpecific["m"] as? Long
                    ?: column.maxByOrNull { (it as Number).toLong() } as Long

                parameterSpec
            }

            FOPE_ALGORITHM_NAME -> {
                val parameterSpec = FOPEParameterSpec()
                parameterSpec.d = (detail.params.cipherSpecific["d"] as? Number)?.toByte()
                    ?: ceil(log2((column.maxByOrNull { (it as Number).toLong() } as Number).toDouble())).toInt()
                        .toByte()
                parameterSpec.tau = detail.params.cipherSpecific["tau"] as? Int ?: parameterSpec.tau

                parameterSpec
            }

            PIORE_ALGORITHM_NAME -> {
                val parameterSpec = PIOREParameterSpec()
                parameterSpec.d = (detail.params.cipherSpecific["d"] as? Number)?.toByte()
                    ?: ceil(log2((column.maxByOrNull { (it as Number).toLong() } as Number).toDouble())).toInt()
                        .toByte()

                parameterSpec
            }

            CRYPTOPAN_ALGORITHM_NAME -> {
                val ipMode = detail.params.cipherSpecific["ip"]
                val parameterSpec = CryptoPAnParameterSpec()
                parameterSpec.maxLength =
                    when (ipMode) {
                        4 -> 4
                        6 -> 16
                        else -> detail.params.cipherSpecific["max_length"] as? Int
                            ?: column.maxByOrNull { (it as String).length } as Int
                    }
                parameterSpec
            }

            HPCBC_ALGORITHM_NAME -> {
                val parameterSpec = HPCBCParameterSpec()
                parameterSpec.integrityCheck = detail.params.cipherSpecific["integrity_check"] as? Boolean ?: false
                parameterSpec.blockSize =
                    detail.params.cipherSpecific["block_size"] as? Int ?: parameterSpec.blockSize
                parameterSpec
            }

            in GaloisJCE.fpeAlgorithms -> {
                val parameterSpec: FPEParameterSpec =
                    if (detail.cipher == DFF_ALGORITHM_NAME) DFFParameterSpec() else FF3ParameterSpec()

                parameterSpec.radix = detail.params.cipherSpecific["radix"] as? Int ?: parameterSpec.radix
                parameterSpec.tweak =
                    (detail.params.cipherSpecific["tweak"] as? String)?.decodeHex()
                        ?: GaloisJCE.random.generateSeed(
                            parameterSpec.maxTLen
                        ).also {
                            detail.params.cipherSpecific["tweak"] = it.toHexString()
                        }

                parameterSpec
            }
            else -> null
        }

    }

    fun tidyConfiguration(): EngineConfiguration {
        configuration.encryptionDetails.forEach {
            if (configuration.mode == Mode.DECRYPT) it.key = null
            when (it.cipher) {
                in GaloisJCE.opeAlgorithms + GaloisJCE.symmetricAlgorithms -> it.params.cipherSpecific.clear()
                CRYPTOPAN_ALGORITHM_NAME -> it.params.cipherSpecific.keys.retainAll(
                    listOf("ip", "suffix", "max_length")
                )
                HPCBC_ALGORITHM_NAME -> it.params.cipherSpecific.keys.retainAll(listOf("ip", "suffix", "block_size"))
                in GaloisJCE.fpeAlgorithms -> it.params.cipherSpecific.keys.retainAll(listOf("radix", "tweak"))
            }
        }
        configuration.mode = if (configuration.mode == Mode.ENCRYPT) Mode.DECRYPT else Mode.ENCRYPT

        return configuration
    }

}

private fun ByteArray.reverseBits(): ByteArray {
    val reverse = ByteArray(size)
    for (j in indices) {
        for (i in 0..7) {
            reverse[lastIndex - j] = reverse[lastIndex - j] shl 1
            reverse[lastIndex - j] = reverse[lastIndex - j] or (this[j] and 0x1)
            this[j] = this[j] shr 1
        }
    }
    return reverse
}

private infix fun Byte.shl(i: Int) = (this.toInt() shl i and 0xFF).toByte()

private infix fun Byte.shr(i: Int) = (this.toInt() shl i and 0xFF).toByte()

