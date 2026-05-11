package at.asitplus.openid

import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd.Companion.FORMAT
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

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
    @SerialName(SupportedCredentialFormat.SerialNames.FORMAT)
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    override val format: CredentialFormatEnum = FORMAT,
) : SupportedCredentialFormat {
    init {
        require(format == FORMAT) {
            "Expected format to be ${FORMAT}, but was $format"
        }
    }

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