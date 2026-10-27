package com.sacca.openfinder.apple

import com.dd.plist.NSArray
import com.dd.plist.NSData
import com.dd.plist.NSDate
import com.dd.plist.NSDictionary
import com.dd.plist.NSNumber
import com.dd.plist.NSObject
import com.dd.plist.NSString
import com.dd.plist.PropertyListParser

/**
 * Apple property lists (XML or binary) as plain Kotlin values: `Map<String, Any?>`, `List<Any?>`, `String`, `Long`,
 * `Double`, `Boolean`, `ByteArray`, `java.util.Date`. Apple's services speak plists; everything above this file sees Kotlin.
 */
object Plist {
    /** @throws IllegalArgumentException when [bytes] is not a plist whose root is a dictionary. */
    fun parseDict(bytes: ByteArray): Map<String, Any?> {
        val root = try { PropertyListParser.parse(bytes) } catch (e: Exception) { throw IllegalArgumentException("not a property list") }
        @Suppress("UNCHECKED_CAST")
        return toKotlin(root) as? Map<String, Any?> ?: throw IllegalArgumentException("property list root is not a dictionary")
    }

    /** XML plist for a dictionary, as `plistlib.dumps(..., fmt=FMT_XML)` writes it. */
    fun toXml(root: Map<String, Any?>): ByteArray = fromKotlin(root).toXMLPropertyList().toByteArray(Charsets.UTF_8)

    private fun toKotlin(o: NSObject?): Any? = when (o) {
        is NSDictionary -> o.entries.associate { (k, v) -> k to toKotlin(v) }
        is NSArray -> o.array.map { toKotlin(it) }
        is NSString -> o.content
        is NSNumber -> when {
            o.isBoolean -> o.boolValue()
            o.isInteger -> o.longValue()
            else -> o.doubleValue()
        }
        is NSData -> o.bytes()
        is NSDate -> o.date
        else -> null
    }

    private fun fromKotlin(v: Any?): NSObject = when (v) {
        is Map<*, *> -> NSDictionary().also { d -> v.forEach { (k, x) -> d[k as String] = fromKotlin(x) } }
        is List<*> -> NSArray(*v.map { fromKotlin(it) }.toTypedArray())
        is String -> NSString(v)
        is Boolean -> NSNumber(v)
        is Int -> NSNumber(v)
        is Long -> NSNumber(v)
        is Double -> NSNumber(v)
        is ByteArray -> NSData(v)
        else -> throw IllegalArgumentException("unsupported plist value: ${v?.javaClass?.simpleName}")
    }
}
