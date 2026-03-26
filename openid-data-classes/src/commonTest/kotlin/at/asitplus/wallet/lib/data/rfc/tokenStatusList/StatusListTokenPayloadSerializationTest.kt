package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private val subject = UniformResourceIdentifier("https://example.com/statuslists/1")
private val issuedAt = Instant.fromEpochSeconds(1_700_000_000)
private val identifierList = IdentifierList(
    identifiers = mapOf(
        Identifier(byteArrayOf(0x01, 0x02)) to IdentifierInfo()
    ),
    aggregationUri = "https://example.com/identifierlists/aggregation",
)

private val identifierListPayload = StatusListTokenPayload(
    subject = subject,
    issuedAt = issuedAt,
    revocationList = identifierList,
)

private val statusListPayload = StatusListTokenPayload(
    subject = subject,
    issuedAt = issuedAt,
    expirationTime = Instant.fromEpochSeconds(1_700_000_600),
    timeToLive = PositiveDuration(60.seconds),
    revocationList = StatusList(
        compressed = byteArrayOf(0x01, 0x02, 0x03),
        statusBitSize = TokenStatusBitSize.ONE,
    ),
)

val StatusListTokenPayloadSerializationTest by testSuite {
    "JSON serialization uses the expected claim names and ttl number format" {
        val json = vckJsonSerializer
            .encodeToJsonElement(StatusListTokenPayload.serializer(), statusListPayload)
            .jsonObject

        json[StatusListTokenPayloadSurrogate.SerialNames.SUBJECT] shouldBe JsonPrimitive(subject.string)
        json[StatusListTokenPayloadSurrogate.SerialNames.ISSUED_AT] shouldBe JsonPrimitive(issuedAt.epochSeconds)
        json[StatusListTokenPayloadSurrogate.SerialNames.EXPIRATION_TIME] shouldBe JsonPrimitive(
            statusListPayload.expirationTime!!.epochSeconds
        )
        json[StatusListTokenPayloadSurrogate.SerialNames.TIME_TO_LIVE] shouldBe JsonPrimitive(60)
    }

    "JSON serialization rejects identifier lists" {
        shouldThrow<SerializationException> {
            vckJsonSerializer.encodeToString(StatusListTokenPayload.serializer(), identifierListPayload)
        }
    }

    "JSON deserialization rejects identifier lists" {
        val json = """
            {
              "sub": "https://example.com/statuslists/1",
              "iat": 1700000000,
              "identifier_list": {}
            }
        """.trimIndent()

        shouldThrow<SerializationException> {
            vckJsonSerializer.decodeFromString<StatusListTokenPayload>(json)
        }
    }

    "JSON deserialization rejects identifier_list even when status_list is present" {
        val validStatusListJson = vckJsonSerializer
            .encodeToJsonElement(StatusListTokenPayload.serializer(), statusListPayload)
            .jsonObject
        val invalidJson = JsonObject(
            validStatusListJson + (StatusListTokenPayloadSurrogate.SerialNames.IDENTIFIER_LIST to JsonObject(emptyMap()))
        )

        shouldThrow<SerializationException> {
            vckJsonSerializer.decodeFromString<StatusListTokenPayload>(invalidJson.toString())
        }
    }

    "CBOR status-list payload uses numeric labels and unsigned ttl values" {
        val encoded = encodeCbor(StatusListTokenPayload.serializer(), statusListPayload)
        val expectedPrefix = buildString {
            append("A5")
            append("02")
            append(encodeCbor(String.serializer(), subject.string))
            append("06")
            append(encodeCbor(Long.serializer(), issuedAt.epochSeconds))
            append("04")
            append(encodeCbor(Long.serializer(), statusListPayload.expirationTime!!.epochSeconds))
            append("19FFFE")
            append(encodeCbor(ULong.serializer(), 60u))
            append("19FFFD")
        }

        encoded.startsWith(expectedPrefix) shouldBe true
    }

    "CBOR identifier-list payload uses numeric labels" {
        val encoded = encodeCbor(StatusListTokenPayload.serializer(), identifierListPayload)
        val expectedPrefix = buildString {
            append("A3")
            append("02")
            append(encodeCbor(String.serializer(), subject.string))
            append("06")
            append(encodeCbor(Long.serializer(), issuedAt.epochSeconds))
            append("19FFFA")
        }

        encoded.startsWith(expectedPrefix) shouldBe true
    }

    "CBOR serialization still supports status lists" {
        val serialized = coseCompliantSerializer.encodeToByteArray(
            StatusListTokenPayload.serializer(),
            statusListPayload,
        )
        val deserialized = coseCompliantSerializer.decodeFromByteArray(
            StatusListTokenPayload.serializer(),
            serialized,
        )

        deserialized shouldBe statusListPayload
    }

    "CBOR serialization still supports identifier lists" {
        val serialized = coseCompliantSerializer.encodeToByteArray(
            StatusListTokenPayload.serializer(),
            identifierListPayload,
        )
        val deserialized = coseCompliantSerializer.decodeFromByteArray(
            StatusListTokenPayload.serializer(),
            serialized,
        )

        deserialized shouldBe identifierListPayload
    }

    "malformed CBOR with both revocation-list variants is rejected" {
        val malformed = buildString {
            append("A4")
            append("02")
            append(encodeCbor(String.serializer(), subject.string))
            append("06")
            append(encodeCbor(Long.serializer(), issuedAt.epochSeconds))
            append("19FFFD")
            append(encodeCbor(StatusList.serializer(), statusListPayload.revocationList as StatusList))
            append("19FFFA")
            append(encodeCbor(IdentifierList.serializer(), identifierList))
        }

        shouldThrowAny {
            coseCompliantSerializer.decodeFromByteArray(
                StatusListTokenPayload.serializer(),
                malformed.decodeToByteArray(Base16Strict),
            )
        }
    }
}

private fun ByteArray.hexUpper() = encodeToString(Base16Strict).uppercase()

private fun <T> encodeCbor(serializer: KSerializer<T>, value: T): String =
    coseCompliantSerializer.encodeToByteArray(serializer, value).hexUpper()
