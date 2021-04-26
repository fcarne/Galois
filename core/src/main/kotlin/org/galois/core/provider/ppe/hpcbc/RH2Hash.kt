package org.galois.core.provider.ppe.hpcbc

import org.galois.core.provider.GaloisJCE
import org.galois.core.provider.util.FluentBitSet
import java.security.SecureRandom
import java.util.*

class RH2Hash(key: ByteArray, private var blockSize: Int) {

    private var k: BitSet
    private var kSquared: BitSet
    private var primitive: BitSet

    private val hashLength get() = blockSize * 8

    init {
        require(key.size in listOf(8, 16)) { "Key size must be 64 or 128, was ${key.size * 8}" }

        val random = SecureRandom.getInstance("SHA1PRNG")
        random.setSeed(key)

        val kBytes = ByteArray(blockSize)
        random.nextBytes(kBytes)
        k = BitSet.valueOf(kBytes)

        primitive = calculatePrimitive(hashLength, random)
        kSquared = finiteMultiplication(k, k)

    }

    private fun calculatePrimitive(hashLength: Int, random: SecureRandom): BitSet {
        val k = random.nextInt(hashLength - 1 - 2) + 2
        return BitSet().apply {
            set(0)
            set(k - 1)
            set(k)
            set(k + 1)
        }
    }

    private fun finiteMultiplication(a: BitSet, b: BitSet): BitSet {
        var f1 = a
        var f2 = b
        val p = BitSet()
        while (f1.cardinality() > 0 && f2.cardinality() > 0) {
            if (f2[0]) // if b is odd, then add the corresponding a to p (final product = sum of all a's corresponding to odd b's)
                p.xor(f1) // since we're in GF(2^m), addition is an XOR
            f2 = FluentBitSet.valueOf(f2).shr(1).bitset // equivalent to b / 2

            val carry = f1[hashLength - 1]
            f1 = FluentBitSet.valueOf(f1).shl(1, hashLength).bitset
            if (carry) f1.xor(primitive)

        }
        return p
    }

    fun digest(bytes: ByteArray): ByteArray {
        var t = kSquared.clone() as BitSet
        val l = (bytes.size + blockSize - 1) / blockSize + 1

        val message = bytes.copyOf(l * blockSize)
        // pads with 0s to reach a multiple of blockSize and as last block the number of bytes padded (except the last block)
        message[message.lastIndex] = (message.size - blockSize - bytes.size).toByte()

        for (i in 0 until l) {
            val mI = message.copyOfRange(i * blockSize, (i + 1) * blockSize)
            t.xor(BitSet.valueOf(mI))
            t = finiteMultiplication(t, k)
        }
        if (l % 2 == 0) t = finiteMultiplication(t, k)

        val hash = ByteArray(blockSize)
        t.toByteArray().apply {
            copyInto(hash, blockSize - size)
        }
        return hash
    }

    class KeyGenerator {
        private lateinit var random: SecureRandom

        fun init(random: SecureRandom) {
            this.random = random
        }

        fun generateKey(keySize: Int): ByteArray {
            if (!this::random.isInitialized) random = GaloisJCE.random
            return random.generateSeed(keySize / 8)
        }
    }

}