package com.sacca.openfinder.apple.cloudkit

import com.sacca.openfinder.apple.cloudkit.CkFixtures.hex
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger

/** The DER reader against `findmy.cloudkit.der` (fixtures/cloudkit/der.json, from tools/oracle/cloudkit_vectors.py). */
class DerOracleTest {
    private val f = CkFixtures.json("der.json")

    private fun assertElement(expected: JSONObject, actual: DerElement, what: String) {
        assertEquals("$what class", expected.getInt("cls"), actual.tagClass)
        assertEquals("$what constructed", expected.getBoolean("constructed"), actual.constructed)
        assertEquals("$what tag", expected.getInt("tag"), actual.tagNumber)
        assertEquals("$what content", expected.getString("content"), hex(actual.content))
        assertEquals("$what raw", expected.getString("raw"), hex(actual.raw))
    }

    @Test fun parsesEverySampleAsPythonDoes() {
        val parsed = f.getJSONObject("parsed")
        for (name in parsed.keys()) {
            val entry = parsed.getJSONObject(name)
            val elements = Der.parseAll(hex(entry.getString("data")))
            val expected = entry.getJSONArray("elements").objects()
            assertEquals(name, expected.size, elements.size)
            expected.zip(elements).forEachIndexed { i, (e, a) -> assertElement(e, a, "$name[$i]") }
            val children = entry.getJSONArray("children")
            elements.forEachIndexed { i, element ->
                if (children.isNull(i)) return@forEachIndexed
                val want = children.getJSONArray(i).objects()
                val got = element.children()
                assertEquals("$name children", want.size, got.size)
                want.zip(got).forEachIndexed { j, (e, a) -> assertElement(e, a, "$name[$i].$j") }
            }
            val ints = entry.getJSONArray("ints")
            val gotInts = elements.filter { it.isUniversal(Der.TAG_INTEGER) }.map { it.asInt() }
            assertEquals(name, (0 until ints.length()).map { BigInteger(ints.get(it).toString()) }, gotInts)
            if (entry.has("sub_ints")) {
                val sub = elements[0].children()
                val want = entry.getJSONArray("sub_ints")
                assertEquals(name, (0 until want.length()).map { BigInteger(want.get(it).toString()) }, sub.filter { it.isUniversal(Der.TAG_INTEGER) }.map { it.asInt() })
                assertEquals(name, entry.getJSONArray("rebuild_without").strings(), sub.indices.map { hex(Der.rebuildWithout(elements[0], it)) })
            }
        }
    }

    @Test fun rejectsWhatPythonRejects() {
        val errors = f.getJSONObject("errors")
        for (name in errors.keys()) {
            val entry = errors.getJSONObject(name)
            val data = hex(entry.getString("data"))
            val got = errorOf {
                when (name) {
                    "children_of_primitive" -> Der.parseOne(data).first.children()
                    "unwrap_two" -> Der.parseOne(data).first.unwrap()
                    "expect_app_wrong" -> Der.expectApplication(data, 1)
                    else -> Der.parseAll(data)
                }
            }
            assertEquals(name, entry.optStringOrNull("error"), got)
        }
    }

    @Test fun encodesLengthsAsPythonDoes() {
        val lengths = f.getJSONObject("encode_length")
        for (n in lengths.keys()) assertEquals(n, lengths.getString(n), hex(Der.encodeLength(n.toInt())))
    }
}
