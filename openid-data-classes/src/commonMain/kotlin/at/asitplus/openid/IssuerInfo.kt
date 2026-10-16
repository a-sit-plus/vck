package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * An attestation about a credential issuer in [IssuerMetadata.issuerInfo], which has the structure of
 * [VerifierInfo] (ETSI TS 119 472-3 V1.1.1, ISS-MDATA-REG_CERT-4.2.3-03), see [OpenIdConstants.IssuerInfo] for its
 * formats.
 */
@Serializable
data class IssuerInfo(
    /** REQUIRED. Identifies the format of the attestation and how it is encoded. */
    @SerialName("format")
    val format: String,

    /**
     * REQUIRED. An object or string containing the attestation, e.g. the registration certificate as a JWT, or the
     * registration information of the registrar as a JSON object (ISS-MDATA-REG_CERT-4.2.3-06, -09).
     */
    @SerialName("data")
    val data: JsonElement,

    /** OPTIONAL. The credential configurations the attestation is relevant for; if omitted, for all of them. */
    @SerialName("credential_ids")
    val credentialIds: Set<String>? = null,
)
