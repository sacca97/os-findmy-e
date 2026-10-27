package com.sacca.openfinder.apple.cloudkit

import java.io.ByteArrayOutputStream
import java.math.BigInteger

/** A DER structure that is not shaped the way it was expected to be (`der.DerError`). */
class DerException(message: String) : Exception(message)

/**
 * One tag-length-value element (port of `findmy.cloudkit.der.DerElement`). [raw] is the element's own bytes, tag and length
 * included: the protection structure's HMAC covers the DER of its members as they arrived.
 */
class DerElement(
    val tagClass: Int,
    val constructed: Boolean,
    val tagNumber: Int,
    val content: ByteArray,
    val raw: ByteArray,
) {
    fun isContext(number: Int) = tagClass == Der.CLASS_CONTEXT && tagNumber == number
    fun isUniversal(number: Int) = tagClass == Der.CLASS_UNIVERSAL && tagNumber == number

    /** This element's content as a sequence of elements. */
    fun children(): List<DerElement> {
        if (!constructed) throw DerException("Cannot read children of a primitive element (tag $tagNumber)")
        return Der.parseAll(content)
    }

    /** Step inside an explicitly tagged element (exactly one child). */
    fun unwrap(): DerElement {
        val inner = children()
        if (inner.size != 1) throw DerException("Expected exactly one element inside tag $tagNumber, got ${inner.size}")
        return inner[0]
    }

    /** INTEGER, signed big-endian; an empty content reads as 0 (as Python). */
    fun asInt(): BigInteger = if (content.isEmpty()) BigInteger.ZERO else BigInteger(content)
    fun asBytes(): ByteArray = content
    fun asString(): String = String(content, Charsets.UTF_8)
}

/**
 * The small DER reader the protection structures need (port of `findmy/cloudkit/der.py`): definite lengths, explicit tags,
 * high tag numbers. Identical acceptance to the Python, including what it rejects (indefinite lengths, truncation).
 */
object Der {
    const val CLASS_UNIVERSAL = 0x00
    const val CLASS_APPLICATION = 0x40
    const val CLASS_CONTEXT = 0x80

    const val TAG_INTEGER = 0x02
    const val TAG_OCTET_STRING = 0x04
    const val TAG_SEQUENCE = 0x10
    const val TAG_SET = 0x11
    const val TAG_UTF8_STRING = 0x0C

    private fun readLength(data: ByteArray, start: Int): Pair<Long, Int> {
        var offset = start
        if (offset >= data.size) throw DerException("Truncated DER: no length byte")
        val first = data[offset].toInt() and 0xff
        offset++
        if (first < 0x80) return first.toLong() to offset
        val numBytes = first and 0x7f
        if (numBytes == 0) throw DerException("Indefinite-length DER is not supported")
        if (offset + numBytes > data.size) throw DerException("Truncated DER: length runs past the end")
        var length = BigInteger.ZERO
        for (i in 0 until numBytes) length = length.shiftLeft(8).or(BigInteger.valueOf((data[offset + i].toInt() and 0xff).toLong()))
        // A length that does not fit is necessarily past the end of any array we hold.
        val asLong = if (length.bitLength() > 62) Long.MAX_VALUE else length.toLong()
        return asLong to offset + numBytes
    }

    /** One element at [start], and the offset just past it. */
    fun parseOne(data: ByteArray, start: Int = 0): Pair<DerElement, Int> {
        var offset = start
        if (offset >= data.size) throw DerException("Truncated DER: no tag byte")
        val identifier = data[offset].toInt() and 0xff
        offset++
        val tagClass = identifier and 0xC0
        val constructed = identifier and 0x20 != 0
        var tagNumber = identifier and 0x1F
        if (tagNumber == 0x1F) {
            tagNumber = 0
            while (true) {
                if (offset >= data.size) throw DerException("Truncated DER: unterminated high tag number")
                val b = data[offset].toInt() and 0xff
                offset++
                tagNumber = (tagNumber shl 7) or (b and 0x7f)
                if (b and 0x80 == 0) break
            }
        }
        val (length, after) = readLength(data, offset)
        offset = after
        if (length > data.size - offset) throw DerException("Truncated DER: element claims $length bytes, ${data.size - offset} remain")
        val end = offset + length.toInt()
        val element = DerElement(tagClass, constructed, tagNumber, data.copyOfRange(offset, end), data.copyOfRange(start, end))
        return element to end
    }

    fun parseAll(data: ByteArray): List<DerElement> {
        val out = ArrayList<DerElement>()
        var offset = 0
        while (offset < data.size) {
            val (element, next) = parseOne(data, offset)
            out += element
            offset = next
        }
        return out
    }

    fun encodeLength(length: Int): ByteArray {
        if (length < 0x80) return byteArrayOf(length.toByte())
        val body = BigInteger.valueOf(length.toLong()).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return byteArrayOf((0x80 or body.size).toByte()) + body
    }

    /** Re-encode a constructed element without member [index], keeping the other members' bytes as they arrived. */
    fun rebuildWithout(element: DerElement, index: Int): ByteArray {
        if (element.raw[0].toInt() and 0x1F == 0x1F) throw DerException("Cannot rebuild an element with a multi-byte tag")
        val body = ByteArrayOutputStream()
        element.children().forEachIndexed { i, child -> if (i != index) body.write(child.raw) }
        val bytes = body.toByteArray()
        return byteArrayOf(element.raw[0]) + encodeLength(bytes.size) + bytes
    }

    /** Parse an `[APPLICATION n] EXPLICIT` wrapper and return what is inside it. */
    fun expectApplication(data: ByteArray, tagNumber: Int): DerElement {
        val (element, _) = parseOne(data)
        if (element.tagClass != CLASS_APPLICATION || element.tagNumber != tagNumber) {
            throw DerException("Expected an [APPLICATION $tagNumber] element, got class 0x%02x tag ${element.tagNumber}".format(element.tagClass))
        }
        return element.unwrap()
    }
}
