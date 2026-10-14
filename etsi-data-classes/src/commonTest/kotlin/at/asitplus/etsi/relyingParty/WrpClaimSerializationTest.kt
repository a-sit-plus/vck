@file:OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)

package at.asitplus.etsi.relyingParty

import at.asitplus.etsi.relyingParty.WrpClaimPathSegment.IndexSegment
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment.NameSegment
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment.WildcardSegment
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.serializer

private val cbor = Cbor(from = Cbor.CoseCompliant) { ignoreUnknownKeys = true }

val WrpClaimSerializationTest by matrixSuite {

    test("JSON claim path decodes names, indices and wildcards") {
        joseCompliantSerializer.decodeFromString<WrpClaimPath>("""["a",0,null]""") shouldBe
                WrpClaimPath(listOf(NameSegment("a"), IndexSegment(0u), WildcardSegment))
    }

    test("JSON claim path keeps numeric strings as names") {
        joseCompliantSerializer.decodeFromString<WrpClaimPath>("""["age_equal_or_over","18"]""") shouldBe
                WrpClaimPath("age_equal_or_over", "18")
        joseCompliantSerializer.decodeFromString<WrpClaimPath>("""["nationalities",18]""") shouldBe
                WrpClaimPath(listOf(NameSegment("nationalities"), IndexSegment(18u)))
    }

    test("JSON claim path encodes canonically") {
        joseCompliantSerializer.encodeToString(
            WrpClaimPath.serializer(),
            WrpClaimPath(listOf(NameSegment("a"), IndexSegment(0u), WildcardSegment, NameSegment("18"))),
        ) shouldBe """["a",0,null,"18"]"""
    }

    test("JSON claim path rejects invalid input") {
        listOf("[]", "[-1]", "[1.5]", "[true]", "[{}]", "[[]]", "[4294967296]").forEach {
            shouldThrow<SerializationException> { joseCompliantSerializer.decodeFromString<WrpClaimPath>(it) }
        }
    }

    test("CBOR claim path decodes names, indices and wildcards") {
        // ["a", 0, null]
        cbor.decodeHex<WrpClaimPath>("836161" + "00" + "f6") shouldBe
                WrpClaimPath(listOf(NameSegment("a"), IndexSegment(0u), WildcardSegment))
    }

    test("CBOR claim path keeps numeric strings as names") {
        cbor.decodeHex<WrpClaimPath>("81" + "623138") shouldBe WrpClaimPath("18")  // ["18"]
        cbor.decodeHex<WrpClaimPath>("81" + "12") shouldBe
                WrpClaimPath(listOf(IndexSegment(18u)))                                     // [18]
    }

    test("CBOR claim path encodes canonically") {
        cbor.encodeToByteArray(
            WrpClaimPath.serializer(),
            WrpClaimPath(listOf(NameSegment("a"), IndexSegment(0u), WildcardSegment)),
        ).toHexString() shouldBe "836161" + "00" + "f6"
    }

    test("CBOR claim path rejects invalid input") {
        listOf(
            "80",           // []
            "8120",         // [-1]
            "81f5",         // [true]
            "81a1616100",   // [{"a": 0}]
            "8180",         // [[]]
            "811b0000000100000000", // [4294967296]
        ).forEach {
            shouldThrow<SerializationException> { cbor.decodeHex<WrpClaimPath>(it) }
        }
    }

    test("CBOR claim path reads an empty map as wildcard, as kotlinx-serialization reads it as null") {
        cbor.decodeHex<WrpClaimPath>("81a0") shouldBe WrpClaimPath(listOf(WildcardSegment))  // [{}]
    }

    test("CBOR claim values reject null, floats and structures") {
        listOf("81f6", "81f93e00", "81a1616100", "8180").forEach {
            shouldThrow<SerializationException> {
                cbor.decodeFromByteArray(ListSerializer(WrpClaimValue.serializer()), it.hexToByteArray())
            }
        }
    }

    test("Claim values decode strings, integers and booleans in JSON and CBOR") {
        val expected = listOf(
            WrpClaimValue.StringValue("Alice"),
            WrpClaimValue.IntegerValue(18),
            WrpClaimValue.BooleanValue(true),
            WrpClaimValue.StringValue("18"),
        )
        val serializer = ListSerializer(WrpClaimValue.serializer())

        joseCompliantSerializer.decodeFromString(serializer, """["Alice",18,true,"18"]""") shouldBe expected
        joseCompliantSerializer.encodeToString(serializer, expected) shouldBe """["Alice",18,true,"18"]"""

        val cborHex = "84" + "65416c696365" + "12" + "f5" + "623138"
        cbor.decodeFromByteArray(serializer, cborHex.hexToByteArray()) shouldBe expected
        cbor.encodeToByteArray(serializer, expected).toHexString() shouldBe cborHex
    }

    test("Claim values reject null, floats and structures") {
        listOf("[null]", "[1.5]", "[{}]", "[[]]").forEach {
            shouldThrow<SerializationException> {
                joseCompliantSerializer.decodeFromString(ListSerializer(WrpClaimValue.serializer()), it)
            }
        }
    }
}

private inline fun <reified T> Cbor.decodeHex(hex: String): T =
    decodeFromByteArray(serializer<T>(), hex.hexToByteArray())
