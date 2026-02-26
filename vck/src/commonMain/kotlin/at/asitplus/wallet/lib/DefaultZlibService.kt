package at.asitplus.wallet.lib

private const val ZLIB_HEADER_CMF = 0x78
private const val ZLIB_HEADER_FLG = 0x9C
private const val MAX_STORED_BLOCK_SIZE = 0xFFFF

/**
 * Pure Kotlin ZLIB service:
 * - RFC1950 container (CMF/FLG + ADLER32 trailer)
 * - RFC1951 DEFLATE payload
 *
 * Compression intentionally emits only "stored" deflate blocks (no LZ/Huffman), which is simple and deterministic.
 * Decompression supports stored, fixed-Huffman, and dynamic-Huffman blocks for interoperability.
 */
class DefaultZlibService : ZlibService {

    /**
     * 5 MB seems to be safe for a max. inflated byte array.
     */
    private val maxDecompressedSize = 5 * 1024 * 1024

    override fun compress(input: ByteArray): ByteArray? = try {
        val output = ByteArrayBuilder(input.size + 16)
        // RFC1950: CMF/FLG for DEFLATE with a common/default window setting.
        output.appendByte(ZLIB_HEADER_CMF)
        output.appendByte(ZLIB_HEADER_FLG)

        if (input.isEmpty()) {
            output.appendStoredBlock(input, 0, 0, isFinal = true)
        } else {
            var offset = 0
            while (offset < input.size) {
                val blockSize = minOf(MAX_STORED_BLOCK_SIZE, input.size - offset)
                val isFinal = offset + blockSize >= input.size
                output.appendStoredBlock(input, offset, blockSize, isFinal)
                offset += blockSize
            }
        }

        // RFC1950 trailer: ADLER32 checksum of the uncompressed payload.
        output.appendUInt32BE(adler32(input))
        output.toByteArray()
    } catch (_: Throwable) {
        null
    }

    override fun decompress(input: ByteArray): ByteArray? = try {
        if (input.size < 6) return null

        val cmf = input[0].toUByte().toInt()
        val flg = input[1].toUByte().toInt()
        if ((cmf and 0x0F) != 0x08) return null
        if (((cmf shl 8) or flg) % 31 != 0) return null
        if ((flg and 0x20) != 0) return null // preset dictionary is unsupported

        // Strip RFC1950 envelope and keep only DEFLATE stream for block decoding.
        val expectedAdler = readUInt32BE(input, input.size - 4)
        val deflateData = input.copyOfRange(2, input.size - 4)
        val reader = BitReader(deflateData)
        val output = ByteAccumulator(maxDecompressedSize)

        while (true) {
            val isFinal = reader.readBits(1) ?: return null
            // BTYPE: 00=stored, 01=fixed Huffman, 10=dynamic Huffman, 11=reserved/invalid
            when (reader.readBits(2) ?: return null) {
                0 -> if (!decompressStoredBlock(reader, output)) return null
                1 -> if (!decompressHuffmanBlock(reader, output, FIXED_LITERAL_LENGTH_TABLE, FIXED_DISTANCE_TABLE)) return null
                2 -> {
                    val tables = readDynamicHuffmanTables(reader) ?: return null
                    if (!decompressHuffmanBlock(reader, output, tables.first, tables.second)) return null
                }

                else -> return null
            }
            if (isFinal == 1) break
        }

        val result = output.toByteArray()
        if (adler32(result) != expectedAdler) return null
        result
    } catch (_: Throwable) {
        null
    }
}

private fun decompressStoredBlock(reader: BitReader, output: ByteAccumulator): Boolean {
    // Stored blocks are byte-aligned by definition.
    reader.alignToByte()
    val lenLow = reader.readByteAligned() ?: return false
    val lenHigh = reader.readByteAligned() ?: return false
    val nLenLow = reader.readByteAligned() ?: return false
    val nLenHigh = reader.readByteAligned() ?: return false
    val len = lenLow or (lenHigh shl 8)
    val nLen = nLenLow or (nLenHigh shl 8)
    if ((len xor 0xFFFF) != nLen) return false

    repeat(len) {
        val value = reader.readByteAligned() ?: return false
        if (!output.append(value)) return false
    }
    return true
}

private fun decompressHuffmanBlock(
    reader: BitReader,
    output: ByteAccumulator,
    literalLengthTable: HuffmanTable,
    distanceTable: HuffmanTable
): Boolean {
    while (true) {
        when (val symbol = literalLengthTable.decode(reader) ?: return false) {
            // Literal byte
            in 0..255 -> if (!output.append(symbol)) return false
            // End-of-block marker
            256 -> return true
            in 257..285 -> {
                // Length/distance pair (LZ77 back-reference)
                val lengthCode = symbol - 257
                val lengthBase = LENGTH_BASE[lengthCode]
                val lengthExtra = LENGTH_EXTRA[lengthCode]
                val length = lengthBase + if (lengthExtra == 0) 0 else (reader.readBits(lengthExtra) ?: return false)

                val distanceSymbol = distanceTable.decode(reader) ?: return false
                if (distanceSymbol !in DISTANCE_BASE.indices) return false
                val distanceExtra = DISTANCE_EXTRA[distanceSymbol]
                val distance = DISTANCE_BASE[distanceSymbol] +
                    if (distanceExtra == 0) 0 else (reader.readBits(distanceExtra) ?: return false)

                if (!output.appendBackReference(distance, length)) return false
            }

            else -> return false
        }
    }
}

private fun readDynamicHuffmanTables(reader: BitReader): Pair<HuffmanTable, HuffmanTable>? {
    // HLIT/HDIST/HCLEN define how many code lengths are transmitted in this block.
    val hlit = (reader.readBits(5) ?: return null) + 257
    val hdist = (reader.readBits(5) ?: return null) + 1
    val hclen = (reader.readBits(4) ?: return null) + 4

    // Read code-length alphabet in RFC-defined permutation order.
    val codeLengthLengths = IntArray(19)
    for (i in 0 until hclen) {
        codeLengthLengths[CODE_LENGTH_ORDER[i]] = reader.readBits(3) ?: return null
    }

    val codeLengthTable = buildHuffmanTable(codeLengthLengths) ?: return null
    val literalAndDistanceLengths = IntArray(hlit + hdist)

    var index = 0
    while (index < literalAndDistanceLengths.size) {
        when (val symbol = codeLengthTable.decode(reader) ?: return null) {
            in 0..15 -> literalAndDistanceLengths[index++] = symbol
            // Repeat previous length 3..6 times
            16 -> {
                if (index == 0) return null
                val repeat = (reader.readBits(2) ?: return null) + 3
                repeat(repeat) {
                    if (index >= literalAndDistanceLengths.size) return null
                    literalAndDistanceLengths[index] = literalAndDistanceLengths[index - 1]
                    index++
                }
            }

            // Repeat length 0 for 3..10 entries
            17 -> {
                val repeat = (reader.readBits(3) ?: return null) + 3
                repeat(repeat) {
                    if (index >= literalAndDistanceLengths.size) return null
                    literalAndDistanceLengths[index++] = 0
                }
            }

            // Repeat length 0 for 11..138 entries
            18 -> {
                val repeat = (reader.readBits(7) ?: return null) + 11
                repeat(repeat) {
                    if (index >= literalAndDistanceLengths.size) return null
                    literalAndDistanceLengths[index++] = 0
                }
            }

            else -> return null
        }
    }

    val literalLengthTable = buildHuffmanTable(literalAndDistanceLengths.copyOfRange(0, hlit)) ?: return null
    val distanceCodeLengths = literalAndDistanceLengths.copyOfRange(hlit, literalAndDistanceLengths.size)
    val distanceTable = if (distanceCodeLengths.all { it == 0 }) {
        // RFC1951 allows a literal-only dynamic block with no distance tree.
        // Any later attempt to decode a length/distance pair will fail naturally.
        EMPTY_DISTANCE_TABLE
    } else {
        buildHuffmanTable(distanceCodeLengths) ?: return null
    }
    return literalLengthTable to distanceTable
}

private class BitReader(private val data: ByteArray) {
    private var byteIndex = 0
    private var bitIndex = 0

    fun readBits(count: Int): Int? {
        var result = 0
        repeat(count) { bit ->
            if (byteIndex >= data.size) return null
            // DEFLATE bits are read LSB-first within each byte.
            val nextBit = (data[byteIndex].toInt() ushr bitIndex) and 0x01
            result = result or (nextBit shl bit)
            bitIndex++
            if (bitIndex == 8) {
                bitIndex = 0
                byteIndex++
            }
        }
        return result
    }

    fun alignToByte() {
        if (bitIndex != 0) {
            bitIndex = 0
            byteIndex++
        }
    }

    fun readByteAligned(): Int? {
        if (bitIndex != 0 || byteIndex >= data.size) return null
        return data[byteIndex++].toUByte().toInt()
    }
}

private class ByteAccumulator(private val maxSize: Int) {
    private var data = ByteArray(1024)
    private var size = 0

    fun append(value: Int): Boolean {
        if (size >= maxSize) return false
        ensureCapacity(1)
        data[size++] = value.toByte()
        return true
    }

    fun appendBackReference(distance: Int, length: Int): Boolean {
        if (distance <= 0 || distance > size) return false
        if (size + length > maxSize) return false

        // Copy may overlap with what we are writing; byte-wise copy handles that correctly.
        ensureCapacity(length)
        repeat(length) {
            data[size] = data[size - distance]
            size++
        }
        return true
    }

    fun toByteArray(): ByteArray = data.copyOf(size)

    private fun ensureCapacity(extra: Int) {
        val target = size + extra
        if (target <= data.size) return
        var capacity = data.size
        while (capacity < target) {
            capacity = (capacity * 2).coerceAtMost(maxSize)
            if (capacity < target && capacity == maxSize) break
        }
        if (capacity < target) throw IllegalArgumentException("Decompression exceeded maximum output size")
        data = data.copyOf(capacity)
    }
}

private class ByteArrayBuilder(initialCapacity: Int) {
    private var data = ByteArray(initialCapacity.coerceAtLeast(16))
    private var size = 0

    fun appendByte(value: Int) {
        ensureCapacity(1)
        data[size++] = value.toByte()
    }

    fun appendUInt32BE(value: UInt) {
        appendByte(((value shr 24) and 0xFFu).toInt())
        appendByte(((value shr 16) and 0xFFu).toInt())
        appendByte(((value shr 8) and 0xFFu).toInt())
        appendByte((value and 0xFFu).toInt())
    }

    fun appendStoredBlock(input: ByteArray, offset: Int, length: Int, isFinal: Boolean) {
        // "Stored" deflate block header:
        // - BFINAL (bit 0)
        // - BTYPE = 00 (bits 1..2)
        // Remaining bits in the byte are padding to next byte boundary.
        appendByte(if (isFinal) 0x01 else 0x00) // BFINAL + BTYPE=00 with byte-alignment padding

        // LEN and one's-complement NLEN are little-endian per RFC1951.
        appendByte(length and 0xFF)
        appendByte((length ushr 8) and 0xFF)
        val nLen = length xor 0xFFFF
        appendByte(nLen and 0xFF)
        appendByte((nLen ushr 8) and 0xFF)

        if (length > 0) {
            ensureCapacity(length)
            input.copyInto(data, size, offset, offset + length)
            size += length
        }
    }

    fun toByteArray(): ByteArray = data.copyOf(size)

    private fun ensureCapacity(extra: Int) {
        val target = size + extra
        if (target <= data.size) return
        var capacity = data.size
        while (capacity < target) {
            capacity *= 2
        }
        data = data.copyOf(capacity)
    }
}

private class HuffmanTable(
    private val symbolByReversedCode: Map<Int, Int>,
    private val maxBits: Int
) {
    fun decode(reader: BitReader): Int? {
        var code = 0
        for (bitLength in 1..maxBits) {
            // Build lookup key incrementally bit-by-bit.
            code = code or ((reader.readBits(1) ?: return null) shl (bitLength - 1))
            symbolByReversedCode[(bitLength shl 16) or code]?.let { return it }
        }
        return null
    }
}

private val EMPTY_DISTANCE_TABLE = HuffmanTable(emptyMap(), 0)

private fun buildHuffmanTable(codeLengths: IntArray): HuffmanTable? {
    val maxBits = codeLengths.maxOrNull() ?: return null
    if (maxBits == 0) return null

    val bitLengthCounts = IntArray(maxBits + 1)
    for (length in codeLengths) {
        if (length < 0 || length > 15) return null
        if (length > 0) bitLengthCounts[length]++
    }

    val nextCode = IntArray(maxBits + 1)
    var code = 0
    for (bits in 1..maxBits) {
        code = (code + bitLengthCounts[bits - 1]) shl 1
        nextCode[bits] = code
    }

    val symbolByCode = HashMap<Int, Int>(codeLengths.size * 2)
    codeLengths.forEachIndexed { symbol, bitLength ->
        if (bitLength == 0) return@forEachIndexed
        val canonicalCode = nextCode[bitLength]++
        // Canonical codes are MSB-oriented, but DEFLATE reads bits LSB-first,
        // so we reverse each code for direct decoding from the bitstream.
        val reversed = reverseBits(canonicalCode, bitLength)
        symbolByCode[(bitLength shl 16) or reversed] = symbol
    }

    return HuffmanTable(symbolByCode, maxBits)
}

private fun reverseBits(value: Int, bitCount: Int): Int {
    var source = value
    var result = 0
    repeat(bitCount) {
        result = (result shl 1) or (source and 1)
        source = source ushr 1
    }
    return result
}

private fun readUInt32BE(data: ByteArray, offset: Int): UInt =
    ((data[offset].toUInt() and 0xFFu) shl 24) or
        ((data[offset + 1].toUInt() and 0xFFu) shl 16) or
        ((data[offset + 2].toUInt() and 0xFFu) shl 8) or
        (data[offset + 3].toUInt() and 0xFFu)

private fun adler32(data: ByteArray): UInt {
    var s1 = 1u
    var s2 = 0u
    data.forEach {
        s1 = (s1 + it.toUByte().toUInt()) % 65521u
        s2 = (s2 + s1) % 65521u
    }
    return (s2 shl 16) or s1
}

// RFC1951 fixed Huffman literal/length alphabet layout.
private val FIXED_LITERAL_LENGTH_TABLE = run {
    val codeLengths = IntArray(288)
    for (i in 0..143) codeLengths[i] = 8
    for (i in 144..255) codeLengths[i] = 9
    for (i in 256..279) codeLengths[i] = 7
    for (i in 280..287) codeLengths[i] = 8
    buildHuffmanTable(codeLengths) ?: error("Failed to build fixed literal/length Huffman table")
}

// RFC1951 fixed Huffman distance alphabet layout.
private val FIXED_DISTANCE_TABLE = run {
    buildHuffmanTable(IntArray(32) { 5 }) ?: error("Failed to build fixed distance Huffman table")
}

// RFC1951 §3.2.7 permutation for reading code-length code lengths.
private val CODE_LENGTH_ORDER = intArrayOf(
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
)

// RFC1951 literal/length base values for symbols 257..285.
private val LENGTH_BASE = intArrayOf(
    3, 4, 5, 6, 7, 8, 9, 10,
    11, 13, 15, 17,
    19, 23, 27, 31,
    35, 43, 51, 59,
    67, 83, 99, 115,
    131, 163, 195, 227,
    258
)

// RFC1951 number of extra bits for literal/length symbols 257..285.
private val LENGTH_EXTRA = intArrayOf(
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1,
    2, 2, 2, 2,
    3, 3, 3, 3,
    4, 4, 4, 4,
    5, 5, 5, 5,
    0
)

// RFC1951 distance base values for symbols 0..29.
private val DISTANCE_BASE = intArrayOf(
    1, 2, 3, 4,
    5, 7, 9, 13,
    17, 25, 33, 49,
    65, 97, 129, 193,
    257, 385, 513, 769,
    1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289,
    16385, 24577
)

// RFC1951 number of extra bits for distance symbols 0..29.
private val DISTANCE_EXTRA = intArrayOf(
    0, 0, 0, 0,
    1, 1, 2, 2,
    3, 3, 4, 4,
    5, 5, 6, 6,
    7, 7, 8, 8,
    9, 9, 10, 10,
    11, 11, 12, 12,
    13, 13
)
