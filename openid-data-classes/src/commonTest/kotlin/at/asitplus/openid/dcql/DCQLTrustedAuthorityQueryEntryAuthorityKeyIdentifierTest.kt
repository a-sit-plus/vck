package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.EncodingException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifierTest by testSuite {
    "given base64url string without padding" - {
        "when creating instance" - {
            "then does so successfully" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8Y"
                ) { string ->
                    val entry = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                        nonEmptyListOf(string)
                    )
                    entry.authorityKeyIdentifiers.first().byteArray shouldBe string.decodeToByteArray(
                        Base64UrlStrict
                    )
                }
            }
        }
    }

    "given base64url string with padding" - {
        "when creating instance" - {
            "then does so successfully" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8Y="
                ) { string ->
                    val entry = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                        nonEmptyListOf(string)
                    )
                    entry.authorityKeyIdentifiers.first().byteArray shouldBe string.decodeToByteArray(
                        Base64UrlStrict
                    )
                }
            }
        }
    }

    "given non-base64url string" - {
        "when creating instance" - {
            "then throws exception" - {
                withData(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8!=",
                ) { string ->
                    shouldThrow<EncodingException> {
                        DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                            nonEmptyListOf(string)
                        )
                    }
                }
            }
        }
    }

    val serializer = DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier.serializer()
    "given serialized version" - {
        "when deserializing as base or derived type" - {
            "then gives same with expected content" - {
                withData(
                    """{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }""",
                ) { string ->
                    val deserialized = Json.decodeFromString(serializer, string)
                    Json.decodeFromString(
                        DCQLTrustedAuthorityQueryEntry.serializer(),
                        string
                    ) shouldBe deserialized

                    val jsonElement = Json.decodeFromString(
                        JsonElement.serializer(),
                        string
                    )
                    deserialized.authorityKeyIdentifiers.first().byteArray shouldBe jsonElement.jsonObject["values"]!!.jsonArray.first().jsonPrimitive.content.decodeToByteArray(
                        Base64UrlStrict
                    )
                }
            }
        }
    }
    "given serialized version with incorrect type discriminator" - {
        "when deserializing as base or derived type" - {
            "then fails deserialization" - {
                withData(
                    """{ "type": "openid_federation", "values": ["https://trustanchor.example.com"] }""",
                    """{ "type": "etsi_tl", "values": ["ttps://lotl.example.com"] }""",
                ) { string ->
                    try {
                        val deserialized = Json.decodeFromString(serializer, string)
                        Json.decodeFromString(
                            DCQLTrustedAuthorityQueryEntry.serializer(),
                            string
                        ) shouldNotBe deserialized
                    } catch (_: Throwable) {
                        // no statement about exception
                    }
                }
            }
        }
    }
}