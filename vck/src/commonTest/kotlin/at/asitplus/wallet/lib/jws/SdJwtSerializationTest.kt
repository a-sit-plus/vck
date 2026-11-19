package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.fromAnyValue
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.random.nextUInt

val SdJwtSerializationTest by matrixSuite {

    "Serialization is correct for String" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"$value""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialization is correct for ByteArray" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16)
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"${value.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialization is correct for Boolean" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = true
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialization is correct for Long" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextLong()
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialization is correct for UInt" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextUInt()
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialization is correct for Example from spec" {
        val salt = "_26bc4LT-ac6q2KI6cBW5es".decodeToByteArray(Base64UrlStrict)
        val name = "family_name"
        val value = "Möbius"
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val disclosure = item.toDisclosure()

        // different whitespaces may lead to a different string, obviously!
        disclosure shouldBe "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"

        "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0".hashDisclosure() shouldBe "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
    }

    "Serialize nested Byte Array" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = listOf(Random.nextBytes(16))
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"${value.first().encodeToString(Base64UrlStrict)}""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Serialize array entry, without claim name" {
        val salt = Random.nextBytes(32)
        val name = null
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem.fromAnyValue(salt, name, value)

        val serialized = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(item)

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldNotContain """"$name""""
        serialized shouldContain """"$value""""
        serialized shouldContain "]"

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)
        deserialized shouldBe item
    }

    "Deserialize array from spec" {
        val input = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"

        val decoded = input.decodeToByteArray(Base64()).decodeToString()
        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(decoded)
        deserialized.claimName.shouldBeNull()
        deserialized.claimValue.jsonPrimitive.content shouldBe "FR"
        deserialized.salt shouldBe "lklxF5jMYlGTPUovMNIvCA"
    }

    "Deserialize nested from spec" {
        val input = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImFkZHJlc3MiLCB7Il9zZCI6IFs" +
                "iWEZjN3pYUG03enpWZE15d20yRXVCZmxrYTVISHF2ZjhVcF9zek5HcXZpZyIsICJiZDF" +
                "FVnpnTm9wVWs0RVczX2VRMm4zX05VNGl1WE9IdjlYYkdITjNnMVRFIiwgImZfRlFZZ3Z" +
                "RV3Z5VnFObklYc0FSbE55ZTdZR3A4RTc3Z1JBamFxLXd2bnciLCAidjRra2JfcFAxamx" +
                "2VWJTanR5YzVicWNXeUEtaThYTHZoVllZN1pUMHRiMCJdfV0"

        val decoded = input.decodeToByteArray(Base64()).decodeToString()
        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(decoded)
        deserialized.claimName shouldBe "address"
        val nestedSd = deserialized.claimValue.jsonObject["_sd"]
            .shouldBeInstanceOf<JsonArray>()
        nestedSd.size shouldBe 4
    }

    "Deserialize keeps a salt that is not base64url, as it only has to be a string (RFC 9901, 4.2.1)" {
        val serialized = """["salt+with/padding==.", "family_name", "Möbius"]"""

        val deserialized = joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(serialized)

        deserialized.salt shouldBe "salt+with/padding==."
        joseCompliantSerializer.encodeToString(deserialized) shouldBe
                """["salt+with/padding==.","family_name","Möbius"]"""
    }

    listOf(
        InvalidDisclosure("a number as salt", """[1234, "family_name", "Möbius"]"""),
        InvalidDisclosure("a boolean as salt", """[true, "Möbius"]"""),
        InvalidDisclosure("null as salt", """[null, "Möbius"]"""),
        InvalidDisclosure("an object as salt", """[{}, "Möbius"]"""),
        InvalidDisclosure("a number as claim name", """["c2FsdA", 5, "Möbius"]"""),
        InvalidDisclosure("a boolean as claim name", """["c2FsdA", false, "Möbius"]"""),
        InvalidDisclosure("null as claim name", """["c2FsdA", null, "Möbius"]"""),
        InvalidDisclosure("one element", """["c2FsdA"]"""),
        InvalidDisclosure("four elements", """["c2FsdA", "family_name", "Möbius", "extra"]"""),
    ).forEach { case ->
        "Deserialize rejects ${case.name} (RFC 9901, 4.2.1, 4.2.2)" {
            shouldThrow<SerializationException> {
                joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(case.serialized)
            }
        }
    }

}

private class InvalidDisclosure(val name: String, val serialized: String)