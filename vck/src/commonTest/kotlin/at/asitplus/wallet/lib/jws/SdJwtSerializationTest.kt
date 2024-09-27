package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random
import kotlin.random.nextUInt

class SdJwtSerializationTest : FreeSpec({

    "Serialization is correct for String" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for ByteArray" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16)
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"${value.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for Boolean" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = true
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for Long" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextLong()
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for UInt" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextUInt()
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize()

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
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

})
