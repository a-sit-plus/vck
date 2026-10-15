@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.etsi

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.etsi.relyingParty.WrpClaimValue
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.Cbor

val WrpClaimSerializationTest by matrixSuite {

    "a claim path is a claims path pointer of names, null for all elements, and indexes" {
        val json = """{"path":["nationalities",null,0],"values":["AT",1,true]}"""

        val claim = joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), json)

        claim.path shouldBe listOf(
            WrpClaimPathSegment.Name("nationalities"),
            WrpClaimPathSegment.AllElements,
            WrpClaimPathSegment.Index(0U),
        )
        claim.values shouldBe listOf(WrpClaimValue.Text("AT"), WrpClaimValue.Integer(1), WrpClaimValue.Bool(true))
        joseCompliantSerializer.encodeToString(WrpClaim.serializer(), claim) shouldBe json
    }

    "a string that looks like a number is a name" {
        joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), """{"path":["0"]}""").path shouldBe
                listOf(WrpClaimPathSegment.Name("0"))
    }

    "negative indexes, fractions, and objects are no claim path segments" {
        listOf("""{"path":[-1]}""", """{"path":[1.5]}""", """{"path":[{}]}""").forEach {
            shouldThrowAny { joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), it) }
        }
    }

    "invalid JSON paths" - {
        listOf("[]", "[-1]", "[1.5]", "[true]", "[{}]", "[[]]", "[4294967296]", "[9223372036854775807]")
            .asData() test { path ->
                shouldThrowAny {
                    joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), """{"path":$path}""")
                }
            }
    }

    "empty paths cannot be constructed" {
        shouldThrowAny { WrpClaim(emptyList()) }
    }

    "CBOR paths preserve names, indices, and null" {
        val serializer = ListSerializer(WrpClaimPathSegment.serializer())
        val wire = "84616100f6623138".hexToByteArray() // ["a", 0, null, "18"]
        val expected = listOf(
            WrpClaimPathSegment.Name("a"), WrpClaimPathSegment.Index(0u),
            WrpClaimPathSegment.AllElements, WrpClaimPathSegment.Name("18"),
        )
        Cbor.CoseCompliant.decodeFromByteArray(serializer, wire) shouldBe expected
        Cbor.CoseCompliant.encodeToByteArray(serializer, expected).toHexString() shouldBe wire.toHexString()
    }

    "maximum index decodes in JSON and CBOR" {
        val expected = WrpClaimPathSegment.Index(UInt.MAX_VALUE)
        joseCompliantSerializer.decodeFromString(WrpClaimPathSegment.serializer(), "4294967295") shouldBe expected
        Cbor.CoseCompliant.decodeFromByteArray(WrpClaimPathSegment.serializer(), "1affffffff".hexToByteArray()) shouldBe expected
    }

    "invalid CBOR paths" - {
        listOf("80", "8120", "81f5", "81f93e00", "81a1616100", "8180", "811b0000000100000000")
            .asData() test { path ->
                shouldThrowAny {
                    Cbor.CoseCompliant.decodeFromByteArray(WrpClaim.serializer(), ("a16470617468" + path).hexToByteArray())
                }
            }
    }

    "CBOR claim values preserve their types" {
        val serializer = ListSerializer(WrpClaimValue.serializer())
        val wire = "8465416c69636512f5623138".hexToByteArray() // ["Alice", 18, true, "18"]
        val expected = listOf(
            WrpClaimValue.Text("Alice"), WrpClaimValue.Integer(18),
            WrpClaimValue.Bool(true), WrpClaimValue.Text("18"),
        )
        Cbor.CoseCompliant.decodeFromByteArray(serializer, wire) shouldBe expected
        Cbor.CoseCompliant.encodeToByteArray(serializer, expected).toHexString() shouldBe wire.toHexString()
    }

    "invalid CBOR values" - {
        listOf("f6", "f93e00", "a0", "a1616100", "80").asData() test { value ->
            shouldThrowAny {
                Cbor.CoseCompliant.decodeFromByteArray(WrpClaimValue.serializer(), value.hexToByteArray())
            }
        }
    }

    "kotlinx CBOR interprets an empty map as null" {
        Cbor.CoseCompliant.decodeFromByteArray(WrpClaimPathSegment.serializer(), "a0".hexToByteArray()) shouldBe
                WrpClaimPathSegment.AllElements
    }

}
