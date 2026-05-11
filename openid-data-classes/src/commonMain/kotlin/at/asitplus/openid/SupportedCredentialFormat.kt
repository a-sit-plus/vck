package at.asitplus.openid

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import kotlinx.serialization.EncodeDefault
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

@Serializable
data class SupportedCredentialFormatSdJwt(
    /**
     * OID4VCI: IETF SD-JWT VC: REQUIRED. String designating the type of a Credential, as defined in
     * (I-D.ietf-oauth-sd-jwt-vc).
     */
    @SerialName(SerialNames.SD_JWT_VC_TYPE)
    val sdJwtVcType: String, // TODO: Better typing?
    @SerialName(SupportedCredentialFormat.SerialNames.SCOPE)
    override val scope: String? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    override val supportedBindingMethods: Set<String>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    override val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.PROOF_TYPES_SUPPORTED)
    override val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_METADATA)
    override val credentialMetadata: CredentialMetadata? = null,
) : SupportedCredentialFormat {
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format = FORMAT

    override fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = copy(
        supportedProofTypes = supportedProofTypes
    )

    override fun withSupportedSigningAlgorithms(
        supportedSigningAlgorithms: Set<SignatureAlgorithm>
    ) = copy(
        supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
            it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
        }.toSet()
    )

    companion object {
        const val FORMAT_IDENTIFIER = "dc+sd-jwt"
        val FORMAT = CredentialFormatEnum.parse(FORMAT_IDENTIFIER) ?: throw IllegalStateException(
            "Expected format identifier `$FORMAT_IDENTIFIER` to represent a valid format, but couldn't find it."
        )
    }

    data object SerialNames {
        const val SD_JWT_VC_TYPE = "vct"
    }
}

@Serializable
data class SupportedCredentialFormatMsoMdoc(
    /**
     * OID4VCI:
     * ISO mDL: REQUIRED. String identifying the Credential type, as defined in (ISO.18013-5).
     */
    @SerialName(SerialNames.DOCTYPE)
    val docType: String, // TODO: Better typing?
    @SerialName(SupportedCredentialFormat.SerialNames.SCOPE)
    override val scope: String? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    override val supportedBindingMethods: Set<String>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    override val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.PROOF_TYPES_SUPPORTED)
    override val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_METADATA)
    override val credentialMetadata: CredentialMetadata? = null,
) : SupportedCredentialFormat {
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format = FORMAT

    override fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = copy(
        supportedProofTypes = supportedProofTypes
    )

    override fun withSupportedSigningAlgorithms(
        supportedSigningAlgorithms: Set<SignatureAlgorithm>
    ) = copy(
        supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
            it.toCoseAlgorithm().getOrNull()?.coseValue?.let { JsonPrimitive(it) }
        }.toSet()
    )

    companion object {
        const val FORMAT_IDENTIFIER = "mso_mdoc"
        val FORMAT = CredentialFormatEnum.parse(FORMAT_IDENTIFIER) ?: throw IllegalStateException(
            "Expected format identifier `${SupportedCredentialFormatSdJwt.Companion.FORMAT_IDENTIFIER}` to represent a valid format, but couldn't find it."
        )
    }

    data object SerialNames {
        const val DOCTYPE = "doctype"
    }
}

@Serializable
data class SupportedCredentialFormatW3cVcJwt(
    /**
     * OID4VCI: W3C VC: REQUIRED. Object containing the detailed description of the Credential type.
     */
    @SerialName(SerialNames.CREDENTIAL_DEFINITION)
    val credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition,
    @SerialName(SupportedCredentialFormat.SerialNames.SCOPE)
    override val scope: String? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    override val supportedBindingMethods: Set<String>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    override val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.PROOF_TYPES_SUPPORTED)
    override val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_METADATA)
    override val credentialMetadata: CredentialMetadata? = null,
) : SupportedCredentialFormat {
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format = FORMAT

    override fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = copy(
        supportedProofTypes = supportedProofTypes
    )

    override fun withSupportedSigningAlgorithms(
        supportedSigningAlgorithms: Set<SignatureAlgorithm>
    ) = copy(
        supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
            it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
        }.toSet()
    )

    companion object {
        const val FORMAT_IDENTIFIER = "jwt_vc_json"
        val FORMAT = CredentialFormatEnum.parse(FORMAT_IDENTIFIER) ?: throw IllegalStateException(
            "Expected format identifier `${SupportedCredentialFormatSdJwt.Companion.FORMAT_IDENTIFIER}` to represent a valid format, but couldn't find it."
        )
    }

    data object SerialNames {
        const val CREDENTIAL_DEFINITION = "credential_definition"
    }
}

//@Serializable
//data class SupportedCredentialFormatW3cVcJwtCredentailDefinition(
//    /**
//     * OID4VCI: type: REQUIRED. Array designating the types a certain credential type supports, according to [VC_DATA],
//     * Section 4.3.
//     *
//     * VC_DATA Section 4.3
//     *     The value of the type property MUST be, or map to (through interpretation of the @context property), one or
//     *     more URIs. If more than one URI is provided, the URIs MUST be interpreted as an unordered set. Syntactic
//     *     conveniences SHOULD be used to ease developer usage. Such conveniences might include JSON-LD terms. It is
//     *     RECOMMENDED that each URI in the type be one which, if dereferenced, results in a document containing
//     *     machine-readable information about the type.
//     */
//    @SerialName(SerialNames.TYPE)
//    val type: Set<String>
//) {
//    object SerialNames {
//        const val TYPE = "type"
//    }
//}

@Serializable
data class SupportedCredentialFormatW3cVcJsonLd(
    /**
     * OID4VCI: W3C VC: REQUIRED. Object containing the detailed description of the Credential type.
     */
    @SerialName(SerialNames.CREDENTIAL_DEFINITION)
    val credentialDefinition: SupportedCredentialFormatW3cVcJsonLdCredentailDefinition,
    @SerialName(SupportedCredentialFormat.SerialNames.SCOPE)
    override val scope: String? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    override val supportedBindingMethods: Set<String>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    override val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.PROOF_TYPES_SUPPORTED)
    override val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_METADATA)
    override val credentialMetadata: CredentialMetadata? = null,
) : SupportedCredentialFormat {
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format = FORMAT

    override fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = copy(
        supportedProofTypes = supportedProofTypes
    )

    override fun withSupportedSigningAlgorithms(
        supportedSigningAlgorithms: Set<SignatureAlgorithm>
    ) = copy(
        supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
            it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
        }.toSet()
    )

    companion object {
        const val FORMAT_IDENTIFIER = "ldp_vc"
        val FORMAT = CredentialFormatEnum.parse(FORMAT_IDENTIFIER) ?: throw IllegalStateException(
            "Expected format identifier `${SupportedCredentialFormatSdJwt.Companion.FORMAT_IDENTIFIER}` to represent a valid format, but couldn't find it."
        )
    }

    data object SerialNames {
        const val CREDENTIAL_DEFINITION = "credential_definition"
    }
}

@Serializable
data class SupportedCredentialFormatW3cVcJwtJsonLd(
    /**
     * OID4VCI: W3C VC: REQUIRED. Object containing the detailed description of the Credential type.
     */
    @SerialName(SerialNames.CREDENTIAL_DEFINITION)
    val credentialDefinition: SupportedCredentialFormatW3cVcJsonLdCredentailDefinition,
    @SerialName(SupportedCredentialFormat.SerialNames.SCOPE)
    override val scope: String? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED)
    override val supportedBindingMethods: Set<String>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED)
    override val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.PROOF_TYPES_SUPPORTED)
    override val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
    @SerialName(SupportedCredentialFormat.SerialNames.CREDENTIAL_METADATA)
    override val credentialMetadata: CredentialMetadata? = null
) : SupportedCredentialFormat {
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format = FORMAT

    override fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) = copy(
        supportedProofTypes = supportedProofTypes
    )

    override fun withSupportedSigningAlgorithms(
        supportedSigningAlgorithms: Set<SignatureAlgorithm>
    ) = copy(
        supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
            it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
        }.toSet()
    )

    companion object {
        const val FORMAT_IDENTIFIER = "jwt_vc_json-ld"
        val FORMAT = CredentialFormatEnum.parse(FORMAT_IDENTIFIER) ?: throw IllegalStateException(
            "Expected format identifier `${SupportedCredentialFormatSdJwt.Companion.FORMAT_IDENTIFIER}` to represent a valid format, but couldn't find it."
        )
    }

    data object SerialNames {
        const val CREDENTIAL_DEFINITION = "credential_definition"
    }
}

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

///**
// * OID4VCI: Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
// * This object contains a list of name/value pairs, where each name is a unique identifier of the supported Credential
// * being described. This identifier is used in the Credential Offer to communicate to the Wallet which Credential is
// * being offered.
// */
//@Serializable
//@ConsistentCopyVisibility
//data class SupportedCredentialFormat2 private constructor(
//    /**
//     * OID4VCI: REQUIRED. A JSON string identifying the format of this credential, e.g. `jwt_vc_json` or `ldp_vc`.
//     * Depending on the format value, the object contains further elements defining the type and (optionally) particular
//     * claims the credential MAY contain, and information how to display the credential.
//     */
//    @SerialName("format")
//    val format: CredentialFormatEnum,
//
//    /**
//     * OID4VCI: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this
//     * particular Credential. The value can be the same across multiple `credential_configurations_supported` objects.
//     * The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the `scope` value.
//     * The Wallet can use this value in the Authorization Request. Scope values in this Credential Issuer metadata MAY
//     * duplicate those in the `scopes_supported` parameter of the Authorization Server.
//     */
//    @SerialName("scope")
//    val scope: String? = null,
//
//    /**
//     * OID4VCI: OPTIONAL. Array of case-sensitive strings that identify how the Credential is bound to the identifier of
//     * the End-User who possesses the Credential as defined in Section 7.1. Support for keys in JWK format (RFC7517) is
//     * indicated by the value `jwk`. Support for keys expressed as a COSE Key object (RFC8152) (for example, used in
//     * ISO.18013-5) is indicated by the value `cose_key`. When Cryptographic Binding Method is a DID, valid values MUST
//     * be a `did:` prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without
//     * a `:` and method-specific-id. For example, support for the DID method with a method-name "example" would be
//     * represented by `did:example`.
//     */
//    @SerialName("cryptographic_binding_methods_supported")
//    val supportedBindingMethods: Set<String>? = null,
//
//    /**
//     * OID4VCI: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the
//     * issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
//     */
//    @SerialName("credential_signing_alg_values_supported")
//    val supportedSigningAlgorithmsJson: Set<JsonElement>? = null,
//
//    /**
//     * OID4VCI: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports.
//     * This object contains a list of name/value pairs, where each name is a unique identifier of the supported
//     * proof type(s).
//     */
//    @SerialName("proof_types_supported")
//    val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
//
//    /**
//     * OID4VCI: W3C VC: REQUIRED.
//     */
//    @SerialName("credential_definition")
//    val credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition? = null,
//
//    /**
//     * OID4VCI: IETF SD-JWT VC: REQUIRED. String designating the type of a Credential, as defined in
//     * (I-D.ietf-oauth-sd-jwt-vc).
//     */
//    @SerialName("vct")
//    val sdJwtVcType: String? = null,
//
//    /**
//     * OID4VCI:
//     * ISO mDL: REQUIRED. String identifying the Credential type, as defined in (ISO.18013-5).
//     */
//    @SerialName("doctype")
//    val docType: String? = null,
//
//    /**
//     * OID4VCI: OPTIONAL. Object containing information relevant to the usage and display of issued Credentials.
//     * Credential Format-specific mechanisms can overwrite the information in this object to convey Credential metadata.
//     * Format-specific mechanisms, such as SD-JWT VC display metadata are always preferred by the Wallet over the
//     * information in this object, which serves as the default fallback.
//     */
//    @SerialName("credential_metadata")
//    val credentialMetadata: CredentialMetadata? = null,
//) {
//
//    /**
//     * OID4VCI: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the
//     * issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
//     */
//    val supportedSigningAlgorithms: Set<SignatureAlgorithm>?
//        get() = supportedSigningAlgorithmsJson?.mapNotNull {
//            (it as? JsonPrimitive)?.content?.let { str ->
//                str.toIntOrNull()?.toCoseAlgorithm()?.toSignatureAlgorithm()
//                    ?: str.toJwsAlgorithm()?.toSignatureAlgorithm()
//            }
//        }?.toSet()
//
//    fun withSupportedProofTypes(supportedProofTypes: Map<String, CredentialRequestProofSupported>) =
//        copy(supportedProofTypes = supportedProofTypes)
//
//    fun withSupportedSigningAlgorithms(supportedSigningAlgorithms: Set<SignatureAlgorithm>) =
//        copy(
//            supportedSigningAlgorithmsJson = supportedSigningAlgorithms.mapNotNull {
//                if (format == CredentialFormatEnum.MSO_MDOC)
//                    it.toCoseAlgorithm().getOrNull()?.coseValue?.let { JsonPrimitive(it) }
//                else
//                    it.toJwsAlgorithm().getOrNull()?.identifier?.let { JsonPrimitive(it) }
//            }.toSet()
//        )
//
//    companion object {
//
//        fun forIsoMdoc(
//            format: CredentialFormatEnum,
//            scope: String,
//            supportedBindingMethods: Set<String>? = null,
//            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
//            credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition? = null,
//            docType: String,
//            isoClaims: Set<ClaimDescription>,
//            display: Set<DisplayProperties>? = null,
//        ) = SupportedCredentialFormat(
//            format = format,
//            scope = scope,
//            supportedBindingMethods = supportedBindingMethods,
//            supportedProofTypes = supportedProofTypes,
//            credentialDefinition = credentialDefinition,
//            docType = docType,
//            credentialMetadata = CredentialMetadata(
//                claimDescription = isoClaims,
//                display = display,
//            )
//        )
//
//        fun forSdJwt(
//            format: CredentialFormatEnum,
//            scope: String,
//            supportedBindingMethods: Set<String>? = null,
//            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
//            credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition? = null,
//            sdJwtVcType: String,
//            sdJwtClaims: Set<ClaimDescription>,
//            display: Set<DisplayProperties>? = null,
//        ) = SupportedCredentialFormat(
//            format = format,
//            scope = scope,
//            supportedBindingMethods = supportedBindingMethods,
//            supportedProofTypes = supportedProofTypes,
//            credentialDefinition = credentialDefinition,
//            sdJwtVcType = sdJwtVcType,
//            credentialMetadata = CredentialMetadata(
//                claimDescription = sdJwtClaims,
//                display = display,
//            )
//        )
//
//        fun forVcJwt(
//            format: CredentialFormatEnum,
//            scope: String,
//            supportedBindingMethods: Set<String>? = null,
//            supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,
//            credentialDefinition: SupportedCredentialFormatW3cVcJwtCredentailDefinition,
//            vcJwtClaims: Set<ClaimDescription>,
//            display: Set<DisplayProperties>? = null,
//        ) = SupportedCredentialFormat(
//            format = format,
//            scope = scope,
//            supportedBindingMethods = supportedBindingMethods,
//            supportedProofTypes = supportedProofTypes,
//            credentialDefinition = credentialDefinition,
//            credentialMetadata = CredentialMetadata(
//                claimDescription = vcJwtClaims,
//                display = display,
//            )
//        )
//
//    }
//}
