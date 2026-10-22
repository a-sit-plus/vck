package at.asitplus.wallet.lib.agent

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElementOrNull
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.toDcqlClaimValue
import at.asitplus.wallet.mdl.IsoSexEnum
import at.asitplus.wallet.mdl.IsoSexEnumSerializer
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Instant

/**
 * OpenID4VP 1.0, 6.3: the CBOR value of an ISO mdoc data element is converted to JSON before it is matched against the
 * `values` of a claims query.
 */
val DCQLIsoMdocValueMatchingTest by matrixSuite {

    "conversion to JSON for matching" - {
        "dates, date-times and byte strings are converted to their string" {
            LocalDate(1990, 1, 1).toJsonElementOrNull() shouldBe JsonPrimitive("1990-01-01")
            Instant.parse("2026-10-22T08:15:30Z").toJsonElementOrNull() shouldBe JsonPrimitive("2026-10-22T08:15:30Z")
            byteArrayOf(-5, -1).toJsonElementOrNull() shouldBe JsonPrimitive("-_8")
        }
        "a type with a registered encoder is converted by it" {
            LibraryInitializer.registerCredentialSerializers(
                jsonValueEncoder = { (it as? RegisteredCode)?.let { JsonPrimitive(it.code) } }
            )
            RegisteredCode(1).toJsonElementOrNull() shouldBe JsonPrimitive(1)
        }
        "a type without an encoding is not converted, instead of being represented by its string" {
            UnknownValue("1").toJsonElementOrNull().shouldBeNull()
            UnknownValue("1").toJsonElement() shouldBe JsonPrimitive("UnknownValue(value=1)")
        }
    }

    "conversion of data elements with their CBOR serializer" - {
        LibraryInitializer.registerCredentialSerializers(
            jsonValueEncoder = {
                when (it) {
                    is TestCode -> JsonPrimitive("CODE_${it.code}")
                    is CborOnlyValue -> JsonPrimitive("display")
                    else -> null
                }
            },
            itemValueSerializerMap = mapOf(
                TEST_NAMESPACE to mapOf(
                    "code" to TestCodeSerializer,
                    "cbor_only" to CborOnlyValueSerializer,
                    "portrait" to ByteArraySerializer(),
                    "sex" to IsoSexEnumSerializer,
                )
            ),
        )
        fun item(elementIdentifier: String, value: Any) =
            IssuerSignedItem(0u, Random.nextBytes(16), elementIdentifier, value)

        "a scheme-specific type is encoded like its CBOR item, not by its display encoder" {
            item("code", TestCode(1)).toDcqlClaimValue(TEST_NAMESPACE) shouldBe JsonPrimitive(1)
        }
        "the mDL sex is encoded as its integer code" {
            item("sex", IsoSexEnum.FEMALE).toDcqlClaimValue(TEST_NAMESPACE) shouldBe JsonPrimitive(IsoSexEnum.FEMALE.code)
        }
        "a serializer that can not encode to JSON falls back to the registered encoder" {
            item("cbor_only", CborOnlyValue).toDcqlClaimValue(TEST_NAMESPACE) shouldBe JsonPrimitive("display")
        }
        "a byte string stays base64url, although its serializer would encode an array" {
            item("portrait", byteArrayOf(-5, -1)).toDcqlClaimValue(TEST_NAMESPACE) shouldBe JsonPrimitive("-_8")
        }
        "a value without any JSON value is null" {
            item("unknown", UnknownValue("1")).toDcqlClaimValue(TEST_NAMESPACE) shouldBe JsonNull
        }
    }

    "values of a stored ISO mdoc" - {
        suspend fun matchesDateOfBirth(expected: String): Boolean {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(keyMaterial = holderKeyMaterial)
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            )
            // issued with date_of_birth 1990-01-01, a full-date (tag 1004)
            holder.storeCredential(issueIsoMdoc(issuer, holderKeyMaterial).toStoreCredentialInput()).getOrThrow()
            val query = Json.decodeFromString<DCQLQuery>(
                """
                {
                  "credentials": [{
                    "id": "mdoc",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "${AtomicAttribute2023.isoDocType}" },
                    "claims": [{
                      "path": ["${AtomicAttribute2023.isoNamespace}", "${AtomicAttribute2023.CLAIM_DATE_OF_BIRTH}"],
                      "values": ["$expected"]
                    }]
                  }]
                }
                """.trimIndent()
            )
            val matching = holder.matchPresentationRequestAgainstCredentialStore(
                CredentialPresentationRequest.DCQLRequest(query)
            ).getOrThrow().shouldBeInstanceOf<at.asitplus.wallet.lib.agent.DCQLMatchingResult<*>>()
            return matching.matchingResult.credentialQueryMatches.values.single().isNotEmpty()
        }

        "a full-date matches its string" {
            matchesDateOfBirth("1990-01-01") shouldBe true
        }
        "a full-date does not match another date" {
            matchesDateOfBirth("1990-01-02") shouldBe false
        }
    }
}

private data class RegisteredCode(val code: Int)

private data class UnknownValue(val value: String)

private const val TEST_NAMESPACE = "at.a-sit.wallet.dcql-value-matching-test"

private data class TestCode(val code: Int)

/** Encodes like a CBOR integer, as e.g. `IsoSexEnumSerializer` does. */
private object TestCodeSerializer : KSerializer<TestCode> {
    override val descriptor = PrimitiveSerialDescriptor("TestCode", PrimitiveKind.INT)
    override fun serialize(encoder: Encoder, value: TestCode) = encoder.encodeInt(value.code)
    override fun deserialize(decoder: Decoder) = TestCode(decoder.decodeInt())
}

private object CborOnlyValue

/** Refuses to encode to JSON, like a serializer relying on features of CBOR. */
private object CborOnlyValueSerializer : KSerializer<CborOnlyValue> {
    override val descriptor = PrimitiveSerialDescriptor("CborOnlyValue", PrimitiveKind.INT)
    override fun serialize(encoder: Encoder, value: CborOnlyValue) {
        if (encoder is JsonEncoder) throw SerializationException("CBOR only")
        encoder.encodeInt(0)
    }
    override fun deserialize(decoder: Decoder) = CborOnlyValue.also { decoder.decodeInt() }
}

