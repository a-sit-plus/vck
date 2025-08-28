package at.asitplus.openid

import at.asitplus.dif.FormatHolder
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VP 1.0: OPTIONAL.
 * A non-empty array of attestations about the Verifier relevant to the Credential Request.
 * These attestations MAY include Verifier metadata, policies, trust status, or authorizations.
 * Attestations are intended to support authorization decisions, inform Wallet policy enforcement,
 * or enrich the End-User consent dialog.
 */
@Serializable
data class VerifierInfo(
    /**
     * OID4VP 1.0: REQUIRED.
     * A string that identifies the format of the attestation and how it is encoded. Ecosystems SHOULD use
     * collision-resistant identifiers. Further processing of the attestation is determined by the type of
     * the attestation, which is specified in a format-specific way.
     */
    @SerialName("format")
    val format: FormatHolder,

    /**
     * OID4VP 1.0: REQUIRED.
     * An object or string containing an attestation (e.g. a JWT). The payload structure is defined on a per
     * format level. It is at the discretion of the Wallet whether it uses the information from verifier_info.
     * Factors that influence such Wallet's decision include, but are not limited to, trust framework the Wallet
     * supports, specific policies defined by the Issuers or ecosystem, and profiles of this specification.
     * If the Wallet uses information from verifier_info, the Wallet MUST validate the signature and ensure binding.
     */
    @SerialName("data")
    val data: String,

    /**
     * OID4VP 1.0: OPTIONAL.
     * A non-empty array of strings each referencing a Credential requested by the Verifier for which the attestation
     * is relevant. Each string matches the id field in a DCQL Credential Query. If omitted, the attestation is relevant
     * to all requested Credentials.
     */
    @SerialName("credential_ids")
    val credentialIds: List<String>,
)
