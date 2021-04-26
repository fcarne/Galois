package org.galois.crypto.provider.util

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*

class FluentBitSet : Cloneable {
    var bitset: BitSet
        private set

    constructor() {
        bitset = BitSet()
    }

    constructor(nbits: Int) {
        bitset = BitSet(nbits)
    }

    private constructor(bitset: BitSet) {
        this.bitset = bitset.clone() as BitSet
    }

    operator fun get(bitIndex: Int): FluentBitSet {
        val newBitSet = FluentBitSet()
        newBitSet.bitset[bitIndex] = bitset[bitIndex]
        return newBitSet
    }

    operator fun get(from: Int, to: Int): FluentBitSet = FluentBitSet(bitset[from, to])

    operator fun set(fromIndex: Int, toIndex: Int): FluentBitSet {
        bitset[fromIndex] = toIndex
        return this
    }

    fun and(set: BitSet): FluentBitSet {
        bitset.and(set)
        return this
    }

    fun and(fluentBitSet: FluentBitSet): FluentBitSet = and(fluentBitSet.bitset)

    fun or(set: BitSet): FluentBitSet {
        bitset.or(set)
        return this
    }

    fun or(fluentBitSet: FluentBitSet): FluentBitSet = or(fluentBitSet.bitset)

    fun xor(set: BitSet): FluentBitSet {
        bitset.xor(set)
        return this
    }

    fun xor(fluentBitSet: FluentBitSet): FluentBitSet = xor(fluentBitSet.bitset)

    fun shl(n: Int, maxBitSize: Int = bitset.length() + n): FluentBitSet {
        val words = bitset.toLongArray()
        val length = (maxBitSize + 63) / 64
        val limit = maxBitSize % 64

        val shifted = LongArray(length)

        val leftPart = n / 64
        val rightPart = leftPart + 1

        for (i in shifted.indices.reversed()) {
            if (i - rightPart >= words.size) continue
            if (n % 64 != 0 && i > rightPart - 1) {
                shifted[i] = shifted[i] or (words[i - rightPart] ushr 64 - n % 64)
            }
            if (i - leftPart >= words.size) continue
            if (i > leftPart - 1) shifted[i] = shifted[i] or (words[i - leftPart] shl n)
        }

        shifted[length - 1] = shifted[length - 1] and (-1L ushr 64 - limit)

        bitset = BitSet.valueOf(shifted)
        return this
    }

    fun shr(n: Int): FluentBitSet {
        val words = bitset.toLongArray()
        val shifted = LongArray(words.size)

        val rightPart = n / 64
        val leftPart = rightPart + 1

        for (i in words.indices) {
            if (i < words.size - rightPart) {
                shifted[i] = shifted[i] or (words[i + rightPart] ushr n)
            }
            if (n % 64 != 0 && i < words.size - leftPart) {
                shifted[i] = shifted[i] or (words[i + leftPart] shl 64 - n % 64)
            }
        }

        bitset = BitSet.valueOf(shifted)
        return this
    }

    fun toByteArray(order: ByteOrder = ByteOrder.BIG_ENDIAN): ByteArray {
        return when {
            ByteOrder.LITTLE_ENDIAN == order -> bitset.toByteArray()
            ByteOrder.BIG_ENDIAN == order -> {
                val words = bitset.toLongArray()
                val n = words.size

                if (n == 0) return ByteArray(0)

                var len = 8 * (n - 1)

                var singleBytes = 0
                var x = words[n - 1]
                while (x != 0L) {
                    singleBytes++
                    x = x ushr 8
                }
                len += singleBytes

                val bytes = ByteArray(len)
                val buffer = ByteBuffer.wrap(bytes)

                for (j in singleBytes - 1 downTo 0) buffer.put((words[n - 1] ushr j * 8 and 0xFF).toByte())
                for (i in n - 2 downTo 0) buffer.putLong(words[i])

                bytes
            }
            else -> throw RuntimeException("Invalid value for ByteOrder: $order")
        }
    }

    override fun toString() = bitset.toString()

    companion object {
        fun valueOf(buffer: ByteBuffer, order: ByteOrder = ByteOrder.BIG_ENDIAN): FluentBitSet {
            return when {
                ByteOrder.LITTLE_ENDIAN == order -> FluentBitSet(BitSet.valueOf(buffer))
                ByteOrder.BIG_ENDIAN == order -> {
                    val byteBuffer = buffer.duplicate()
                    var n = byteBuffer.capacity()
                    val words = LongArray((n + 7) / 8)
                    var i = 0
                    while (n >= 8) {
                        words[i++] = byteBuffer.getLong(n - 8)
                        n -= 8
                    }
                    for (j in n downTo 1) words[i] = words[i] or (byteBuffer[j - 1].toLong() and 0xFF shl (n - j) * 8)

                    FluentBitSet(BitSet.valueOf(words))
                }
                else -> throw RuntimeException("Invalid value for ByteOrder: $order")
            }

        }

        fun valueOf(bytes: ByteArray, order: ByteOrder = ByteOrder.BIG_ENDIAN): FluentBitSet =
            valueOf(ByteBuffer.wrap(bytes), order)

        fun valueOf(bitSet: BitSet): FluentBitSet = FluentBitSet(bitSet)
    }
}