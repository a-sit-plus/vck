package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.random.nextUInt

class SdJwtSerializationTest : FreeSpec({

    "Serialization is correct for String" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val disclosure = item.toDisclosure()

        // different whitespaces may lead to a different string, obviously!
        disclosure shouldBe "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd"

        "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0".hashDisclosure() shouldBe "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
    }

    "Serialize nested Byte Array" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = listOf(Random.nextBytes(16))
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = vckJsonSerializer.encodeToString<SelectiveDisclosureItem>(item)

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
        deserialized.salt shouldBe "lklxF5jMYlGTPUovMNIvCA".decodeToByteArray(Base64UrlStrict)
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

})
