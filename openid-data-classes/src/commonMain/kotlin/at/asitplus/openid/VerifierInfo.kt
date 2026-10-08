package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmOverloads

/**
 * OID4VP 1.0: OPTIONAL.
 * A non-empty array of attestations about the Verifier relevant to the Credential Request.
 * These attestations MAY include Verifier metadata, policies, trust status, or authorizations.
 * Attestations are intended to support authorization decisions, inform Wallet policy enforcement,
 * or enrich the End-User consent dialog.
 */
@Serializable
data class VerifierInfo @JvmOverloads constructor(
    /**
     * OID4VP 1.0: REQUIRED.
     * A string that identifies the format of the attestation and how it is encoded. Ecosystems SHOULD use
     * collision-resistant identifiers. Further processing of the attestation is determined by the type of
     * the attestation, which is specified in a format-specific way.
     */
    @SerialName("format")
    val format: String,

    /**
     * OID4VP 1.0: REQUIRED.
     * An object or string containing an attestation (e.g. a JWT). The payload structure is defined on a per
     * format level. It is at the discretion of the Wallet whether it uses the information from [VerifierInfo].
     * Factors that influence such Wallet's decision include, but are not limited to, trust framework the Wallet
     * supports, specific policies defined by the Issuers or ecosystem, and profiles of this specification.
     * If the Wallet uses information from [VerifierInfo], the Wallet MUST validate the signature and ensure binding.
     */
    @SerialName("data")
    val data: Data,

    /**
     * OID4VP 1.0: OPTIONAL.
     * A non-empty array of strings each referencing a Credential requested by the Verifier for which the attestation
     * is relevant. Each string matches the `id` field in a DCQL Credential Query
     * (see [at.asitplus.openid.dcql.DCQLCredentialQuery.id]). If omitted, the attestation is relevant to all requested
     * Credentials.
     */
    @SerialName("credential_ids")
    val credentialIds: Set<String>? = null,
) {
    /** Attestation in [data] given as a string, e.g. a JWT. */
    @JvmOverloads
    constructor(
        format: String,
        data: String,
        credentialIds: Set<String>? = null,
    ) : this(format = format, data = Data.StringData(data), credentialIds = credentialIds)

    /** Attestation in [data] given as a JSON object. */
    @JvmOverloads
    constructor(
        format: String,
        data: JsonObject,
        credentialIds: Set<String>? = null,
    ) : this(format = format, data = Data.ObjectData(data), credentialIds = credentialIds)

    /**
     * Content of [VerifierInfo.data], which OID4VP 1.0 defines as an object or a string.
     * Interpreting it is up to a parser for the respective [format].
     */
    @Serializable(with = VerifierInfoDataSerializer::class)
    sealed interface Data {
        /** Attestation given as a JSON string, e.g. a JWT. */
        data class StringData(val value: String) : Data

        /** Attestation given as a JSON object. */
        data class ObjectData(val value: JsonObject) : Data
    }
}

/**
 * Serializes [VerifierInfo.Data] as a JSON string or a JSON object, rejecting any other JSON value.
 */
object VerifierInfoDataSerializer : KSerializer<VerifierInfo.Data> {
    override val descriptor: SerialDescriptor = SerialDescriptor(
        serialName = "at.asitplus.openid.VerifierInfo.Data",
        original = JsonElement.serializer().descriptor,
    )

    override fun serialize(encoder: Encoder, value: VerifierInfo.Data) {
        if (encoder !is JsonEncoder) throw SerializationException("VerifierInfo.Data can only be encoded to JSON")
        encoder.encodeJsonElement(
            when (value) {
                is VerifierInfo.Data.StringData -> JsonPrimitive(value.value)
                is VerifierInfo.Data.ObjectData -> value.value
            }
        )
    }

    override fun deserialize(decoder: Decoder): VerifierInfo.Data {
        if (decoder !is JsonDecoder) throw SerializationException("VerifierInfo.Data can only be decoded from JSON")
        val element = decoder.decodeJsonElement()
        return when {
            element is JsonObject -> VerifierInfo.Data.ObjectData(element)
            element is JsonPrimitive && element.isString -> VerifierInfo.Data.StringData(element.content)
            else -> throw SerializationException("verifier_info data must be a string or an object, but is $element")
        }
    }
}
