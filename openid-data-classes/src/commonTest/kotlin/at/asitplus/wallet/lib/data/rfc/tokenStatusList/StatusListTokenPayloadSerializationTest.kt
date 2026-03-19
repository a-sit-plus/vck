package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
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
    "claim names stay aligned with the removed JWT wrappers" {
        StatusListTokenPayloadSurrogate.SerialNames.SUBJECT shouldBe "sub"
        StatusListTokenPayloadSurrogate.SerialNames.ISSUED_AT shouldBe "iat"
        StatusListTokenPayloadSurrogate.SerialNames.EXPIRATION_TIME shouldBe "exp"
        StatusListTokenPayloadSurrogate.SerialNames.TIME_TO_LIVE shouldBe "ttl"
        StatusListTokenPayloadSurrogate.SerialNames.STATUS_LIST shouldBe "status_list"
        StatusListTokenPayloadSurrogate.SerialNames.IDENTIFIER_LIST shouldBe "identifier_list"
    }

    "cbor labels stay aligned with the removed CWT wrappers" {
        StatusListTokenPayloadSurrogate.CborLabels.SUBJECT shouldBe 2L
        StatusListTokenPayloadSurrogate.CborLabels.ISSUED_AT shouldBe 6L
        StatusListTokenPayloadSurrogate.CborLabels.EXPIRATION_TIME shouldBe 4L
        StatusListTokenPayloadSurrogate.CborLabels.TIME_TO_LIVE shouldBe 65534L
        StatusListTokenPayloadSurrogate.CborLabels.STATUS_LIST shouldBe 65533L
        StatusListTokenPayloadSurrogate.CborLabels.IDENTIFIER_LIST shouldBe 65530L
    }

    "surrogate round-trips status lists" {
        StatusListTokenPayloadSurrogate(statusListPayload).toStatusListTokenPayload() shouldBe statusListPayload
    }

    "surrogate round-trips identifier lists" {
        StatusListTokenPayloadSurrogate(identifierListPayload).toStatusListTokenPayload() shouldBe identifierListPayload
    }

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
        val exception = shouldThrow<SerializationException> {
            vckJsonSerializer.encodeToString(StatusListTokenPayload.serializer(), identifierListPayload)
        }
        exception.message shouldBe "IdentifierList is only supported in CBOR"
    }

    "JSON deserialization rejects identifier lists" {
        val json = """
            {
              "sub": "https://example.com/statuslists/1",
              "iat": 1700000000,
              "identifier_list": {}
            }
        """.trimIndent()

        val exception = shouldThrow<SerializationException> {
            vckJsonSerializer.decodeFromString<StatusListTokenPayload>(json)
        }
        exception.message shouldBe "IdentifierList is only supported in CBOR"
    }

    "JSON deserialization rejects identifier_list even when status_list is present" {
        val validStatusListJson = vckJsonSerializer
            .encodeToJsonElement(StatusListTokenPayload.serializer(), statusListPayload)
            .jsonObject
        val invalidJson = JsonObject(
            validStatusListJson + (StatusListTokenPayloadSurrogate.SerialNames.IDENTIFIER_LIST to JsonObject(emptyMap()))
        )

        val exception = shouldThrow<SerializationException> {
            vckJsonSerializer.decodeFromString<StatusListTokenPayload>(invalidJson.toString())
        }
        exception.message shouldBe "IdentifierList is only supported in CBOR"
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
}
