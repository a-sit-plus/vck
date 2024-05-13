package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

class SdJwtSerializationTest : FreeSpec({

    "Serialization is correct for String" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextBytes(16).encodeToString(Base64())
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize().also { println(it) }

        serialized shouldContain "["
        serialized shouldContain """"${salt.encodeToString(Base64UrlStrict)}""""
        serialized shouldContain """"$name""""
        serialized shouldContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for Boolean" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = true
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize().also { println(it) }

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

    "Serialization is correct for Number" {
        val salt = Random.nextBytes(32)
        val name = Random.nextBytes(16).encodeToString(Base64())
        val value = Random.nextLong()
        val item = SelectiveDisclosureItem(salt, name, value)

        val serialized = item.serialize().also { println(it) }

        serialized shouldContain "["
        serialized shouldContain """$value"""
        serialized shouldNotContain """"$value""""
        serialized shouldContain "]"

        val deserialized = SelectiveDisclosureItem.deserialize(serialized).getOrThrow()
        deserialized shouldBe item
    }

})
