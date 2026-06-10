package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.EncodingException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifierTest by matrixSuite {
    val serializer = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier.serializer()
    "given unserialized version when serializing as base type works" - {
        listOf(DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                values = nonEmptyListOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y")
            )).asData() test {
            val pseudoSerialized = Json.encodeToJsonElement(serializer, it)
            val pseudoSerializedBase = Json.encodeToJsonElement(DCQLTrustedAuthorityQueryEntry.serializer(), it)
            pseudoSerialized shouldBe pseudoSerializedBase

            val jsonElement = Json.encodeToJsonElement<DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier>(it)
            it.values.shouldBeSingleton().first() shouldBe jsonElement.jsonObject["values"].shouldNotBeNull()
                .jsonArray.shouldBeSingleton().first().jsonPrimitive.content
        }
    }
    "given base64url string without padding when creating instance works" - {
        listOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y").asData() test { string ->
            val entry = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(nonEmptyListOf(string))
            entry.authorityKeyIdentifiers.shouldBeSingleton().first().byteArray shouldBe
                    string.decodeToByteArray(Base64UrlStrict)
        }
    }

    "given base64url string with padding when creating instance works" - {
        listOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y=").asData() test { string ->
            val entry = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(nonEmptyListOf(string))
            entry.authorityKeyIdentifiers.shouldBeSingleton().first().byteArray shouldBe
                    string.decodeToByteArray(Base64UrlStrict)
        }
    }

    "given non-base64url string when creating instance throws exception" - {
        listOf("s9tIpPmhxdiuNkHMEWNpYim8S8!=").asData() test { string ->
            shouldThrow<EncodingException> {
                DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(nonEmptyListOf(string))
            }
        }
    }

    "given serialized version when deserializing as base works" - {
        listOf("""{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }""").asData() test { string ->
            val deserialized = Json.decodeFromString(serializer, string)
            deserialized shouldBe Json.decodeFromString(DCQLTrustedAuthorityQueryEntry.serializer(), string)

            val jsonElement = Json.decodeFromString(JsonElement.serializer(), string)
            deserialized.authorityKeyIdentifiers.shouldBeSingleton().first().byteArray shouldBe
                    jsonElement.jsonObject["values"].shouldNotBeNull()
                        .jsonArray.shouldBeSingleton().first()
                        .jsonPrimitive.content.decodeToByteArray(Base64UrlStrict)
        }
    }
}
