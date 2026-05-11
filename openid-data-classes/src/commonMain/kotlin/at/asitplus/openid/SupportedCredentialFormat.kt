package at.asitplus.openid

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable(with = SupportedCredentialFormat.FormatDisambiguatingSerializer::class)
sealed interface SupportedCredentialFormat {
    /**
     * OID4VCI: REQUIRED. A JSON string identifying the format of this credential, e.g. `jwt_vc_json` or `ldp_vc`.
     * Depending on the format value, the object contains further elements defining the type and (optionally) particular
     * claims the credential MAY contain, and information how to display the credential.
     */
    @SerialName(SerialNames.FORMAT)
    val format: CredentialFormatEnum

    /**
     * OID4VCI: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this
     * particular Credential. The value can be the same across multiple `credential_configurations_supported` objects.
     * The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the `scope` value.
     * The Wallet can use this value in the Authorization Request. Scope values in this Credential Issuer metadata MAY
     * duplicate those in the `scopes_supported` parameter of the Authorization Server.
     */
    @SerialName(SerialNames.SCOPE)
    val scope: String?

    /**
     * OID4VCI: OPTIONAL. Array of case-sensitive strings that identify how the Credential is bound to the identifier of
     * the End-User who possesses the Credential as defined in Section 7.1. Support for keys in JWK format (RFC7517) is
     * indicated by the value `jwk`. Support for keys expressed as a COSE Key object (RFC8152) (for example, used in
     * ISO.18013-5) is indicated by the value `cose_key`. When Cryptographic Binding Method is a DID, valid values MUST
     * be a `did:` prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without
     * a `:` and method-specific-id. For example, support for the DID method with a method-name "example" would be
     * represented by `did:example`.
     */
    @SerialName(SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    val supportedBindingMethods: Set<String>?

    /**
     * OID4VCI: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the
     * issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
     */
    @SerialName(SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    val supportedSigningAlgorithmsJson: Set<JsonElement>?

    /**
     * OID4VCI: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports.
     * This object contains a list of name/value pairs, where each name is a unique identifier of the supported
     * proof type(s).
     */
    @SerialName(SerialNames.PROOF_TYPES_SUPPORTED)
    val supportedProofTypes: Map<String, CredentialRequestProofSupported>?

    /**
     * OID4VCI: OPTIONAL. Object containing information relevant to the usage and display of issued Credentials.
     * Credential Format-specific mechanisms can overwrite the information in this object to convey Credential metadata.
     * Format-specific mechanisms, such as SD-JWT VC display metadata are always preferred by the Wallet over the
     * information in this object, which serves as the default fallback.
     */
    @SerialName(SerialNames.CREDENTIAL_METADATA)
    val credentialMetadata: CredentialMetadata?

    data object SerialNames {
        const val FORMAT = "format"
        const val SCOPE = "scope"
        const val CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED = "cryptographic_binding_methods_supported"
        const val CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED = "credential_signing_alg_values_supported"
        const val PROOF_TYPES_SUPPORTED = "proof_types_supported"
        const val CREDENTIAL_METADATA = "credential_metadata"
    }

    companion object {
        fun forIsoMdoc(
            scope: String,
            supportedBindingMethods: Set<String>? = null,
            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
            docType: String,
            isoClaims: Set<ClaimDescription>,
            display: Set<DisplayProperties>? = null,
        ) = SupportedCredentialFormatMsoMdoc(
            scope = scope,
            supportedBindingMethods = supportedBindingMethods,
            supportedProofTypes = supportedProofTypes,
            docType = docType,
            credentialMetadata = CredentialMetadata(
                claimDescription = isoClaims,
                display = display,
            )
        )

        fun forSdJwt(
            scope: String,
            supportedBindingMethods: Set<String>? = null,
            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
            credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition? = null,
            sdJwtVcType: String,
            sdJwtClaims: Set<ClaimDescription>,
            display: Set<DisplayProperties>? = null,
        ) = SupportedCredentialFormatSdJwt(
            scope = scope,
            supportedBindingMethods = supportedBindingMethods,
            supportedProofTypes = supportedProofTypes,
            sdJwtVcType = sdJwtVcType,
            credentialMetadata = CredentialMetadata(
                claimDescription = sdJwtClaims,
                display = display,
            )
        )

        fun forVcJwt(
            scope: String,
            supportedBindingMethods: Set<String>? = null,
            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
            credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition,
            vcJwtClaims: Set<ClaimDescription>,
            display: Set<DisplayProperties>? = null,
        ) = SupportedCredentialFormatW3cVcJwt(
            scope = scope,
            supportedBindingMethods = supportedBindingMethods,
            supportedProofTypes = supportedProofTypes,
            credentialDefinition = credentialDefinition,
            credentialMetadata = CredentialMetadata(
                claimDescription = vcJwtClaims,
                display = display,
            )
        )
    }

    /**
     * OID4VCI: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the
     * issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
     */
    val supportedSigningAlgorithms: Set<SignatureAlgorithm>?
        get() = supportedSigningAlgorithmsJson?.mapNotNull {
            (it as? JsonPrimitive)?.content?.let { str ->
                str.toIntOrNull()?.toCoseAlgorithm()?.toSignatureAlgorithm()
                    ?: str.toJwsAlgorithm()?.toSignatureAlgorithm()
            }
        }?.toSet()

    fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = when (this) {
        is SupportedCredentialFormatMsoMdoc -> copy(supportedProofTypes = supportedProofTypes)
        is SupportedCredentialFormatSdJwt -> copy(supportedProofTypes = supportedProofTypes)
        is SupportedCredentialFormatW3cVcJsonLd -> copy(supportedProofTypes = supportedProofTypes)
        is SupportedCredentialFormatW3cVcJwt -> copy(supportedProofTypes = supportedProofTypes)
        is SupportedCredentialFormatW3cVcJwtJsonLd -> copy(supportedProofTypes = supportedProofTypes)
    }

    fun withSupportedSigningAlgorithms(supportedSigningAlgorithms: Set<SignatureAlgorithm>): SupportedCredentialFormat {
        val newSigningAlgorithms = supportedSigningAlgorithms.mapNotNull {
            if (format == CredentialFormatEnum.MSO_MDOC) {
                it.toCoseAlgorithm().getOrNull()?.coseValue?.let { JsonPrimitive(it) }
            } else {
                it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
            }
        }.toSet()

        return when (this) {
            is SupportedCredentialFormatMsoMdoc -> copy(supportedSigningAlgorithmsJson = newSigningAlgorithms)
            is SupportedCredentialFormatSdJwt -> copy(supportedSigningAlgorithmsJson = newSigningAlgorithms)
            is SupportedCredentialFormatW3cVcJsonLd -> copy(supportedSigningAlgorithmsJson = newSigningAlgorithms)
            is SupportedCredentialFormatW3cVcJwt -> copy(supportedSigningAlgorithmsJson = newSigningAlgorithms)
            is SupportedCredentialFormatW3cVcJwtJsonLd -> copy(supportedSigningAlgorithmsJson = newSigningAlgorithms)
        }
    }

    class FormatDisambiguatingSerializer : KSerializer<SupportedCredentialFormat> {
        override val descriptor: SerialDescriptor
            get() = SerialDescriptor(
                original = JsonElement.serializer().descriptor,
                serialName = FormatDisambiguatingSerializer::class.qualifiedName!!,
            )

        override fun serialize(
            encoder: Encoder,
            value: SupportedCredentialFormat
        ) {
            when (value) {
                is SupportedCredentialFormatMsoMdoc -> encoder.encodeSerializableValue(
                    SupportedCredentialFormatMsoMdoc.serializer(),
                    value,
                )

                is SupportedCredentialFormatSdJwt -> encoder.encodeSerializableValue(
                    SupportedCredentialFormatSdJwt.serializer(),
                    value,
                )

                is SupportedCredentialFormatW3cVcJsonLd -> encoder.encodeSerializableValue(
                    SupportedCredentialFormatW3cVcJsonLd.serializer(),
                    value,
                )

                is SupportedCredentialFormatW3cVcJwt -> encoder.encodeSerializableValue(
                    SupportedCredentialFormatW3cVcJwt.serializer(),
                    value,
                )

                is SupportedCredentialFormatW3cVcJwtJsonLd -> encoder.encodeSerializableValue(
                    SupportedCredentialFormatW3cVcJwtJsonLd.serializer(),
                    value,
                )
            }
        }

        override fun deserialize(decoder: Decoder): SupportedCredentialFormat {
            require(decoder is JsonDecoder) {
                "Expected decoder to be JsonDecoder, but got $decoder."
            }
            val jsonObject = decoder.decodeJsonElement().jsonObject
            val formatIdentifier = jsonObject[SerialNames.FORMAT]?.jsonPrimitive
            val format = formatIdentifier?.runCatching {
                CredentialFormatEnum.parse(formatIdentifier.content)
            }?.getOrNull()

            require(format != null) {
                "Expected a supported format identifier under the key `${SerialNames.FORMAT}`, but got `$formatIdentifier`."
            }

            return decoder.json.decodeFromJsonElement(
                when (format) {
                    CredentialFormatEnum.JWT_VC -> SupportedCredentialFormatW3cVcJwt.serializer()
                    CredentialFormatEnum.DC_SD_JWT -> SupportedCredentialFormatSdJwt.serializer()
                    CredentialFormatEnum.JWT_VC_JSON_LD -> SupportedCredentialFormatW3cVcJwtJsonLd.serializer()
                    CredentialFormatEnum.JSON_LD -> SupportedCredentialFormatW3cVcJsonLd.serializer()
                    CredentialFormatEnum.MSO_MDOC -> SupportedCredentialFormatMsoMdoc.serializer()
                    CredentialFormatEnum.NONE -> throw UnsupportedOperationException(
                        "Unsupported format identifier `$formatIdentifier`."
                    )
                },
                jsonObject,
            )
        }
    }
}
