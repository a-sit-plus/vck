package at.asitplus.etsi.relyingParty

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * ETSI TS 119 475 V1.2.1 Annex C WRPRC payload.
 */
@Serializable
data class WrpPayload(
    /** Trade name, common name or service name of the relying party (Table 7; clause B.2.1). */
    @SerialName("name")
    val name: String? = null,

    /** Officially recorded legal name, when the relying party is a legal person (Table 7; clause B.2.3). */
    @SerialName("sub_ln")
    val subjectLegalName: String? = null,

    /** Officially recorded given names, including middle names, for a natural person (Table 7; clause B.2.4). */
    @SerialName("sub_gn")
    val subjectGivenName: String? = null,

    /** Officially recorded family names or surnames for a natural person (Table 7; clause B.2.4). */
    @SerialName("sub_fn")
    val subjectFamilyName: String? = null,

    /** Registered identifier of the relying party on whose behalf data access occurs, even via an intermediary (Table 7). */
    @SerialName("sub")
    val subjectIdentifier: String,

    /** ISO 3166-1 alpha-2 country of establishment, or "EU" for providers operating at European level (clause B.2.2). */
    @SerialName("country")
    val country: String,

    /** URL of the national registry API endpoint for the registered relying party (Table 7). */
    @SerialName("registry_uri")
    val registryUri: String,

    /**
     * Service descriptions, each containing localized versions of the same description (Table 7; clause B.2.1).
     * Also decoded from a single array of localized descriptions, as one service description.
     */
    @SerialName("srv_description")
    @Serializable(with = WrpServiceDescriptionsSerializer::class)
    val srvDescription: List<List<WrpLangString>>,

    /** Entitlement identifiers assigned to the relying party as specified in Annex A (Table 7). */
    @SerialName("entitlements")
    val entitlements: List<String>,

    /** URL of the privacy policy explaining data processing and storage practices (Table 7). */
    @SerialName("privacy_policy")
    val privacyPolicy: String,

    /**
     * General-purpose URL providing public information about the relying party (Table 7), absent when the registry
     * provides none (infoURI `[0..*]`, clause B.2.2).
     */
    @SerialName("info_uri")
    val infoUri: String? = null,

    /** URL or email address for data deletion or portability requests (Table 7; supportURI `[1..*]`, clause B.2.1). */
    @SerialName("support_uri")
    val supportUri: String,

    /**
     * Contact details of the competent data protection supervisory authority (Table 7; supervisoryAuthority `[1..1]`,
     * clause B.2.1).
     */
    @SerialName("supervisory_authority")
    val supervisoryAuthority: WrpSupervisoryAuthority,

    /**
     * Certificate policy identifiers applicable to the WRPRC (Table 7), which include
     * [WrpConstants.POLICY_IDENTIFIER] (clause 6.1.3, OVR-6.1.3-01). Without a default, so that it is always
     * encoded and never assumed when absent.
     */
    @SerialName("policy_id")
    val policyId: List<String>,

    /** URL of the certificate policy and certification practice statement (Table 7). */
    @SerialName("certificate_policy")
    val certificatePolicy: String,

    /** Time the WRPRC was issued, encoded as a Unix timestamp (Table 7). */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val iat: Instant,

    /** Status list reference conveying the validity of the WRPRC (Table 7; Annex C). */
    @SerialName("status")
    val status: WrpStatus,

    /**
     * Localized descriptions of data processing associated with the intended use, only for service providers
     * (Table 9, GEN-5.2.4-06); non-empty when present (purpose `[1..*]`, clause B.2.7).
     */
    @SerialName("purpose")
    val purpose: List<WrpLangString>? = null,

    /**
     * Credential queries describing what the relying party may request, used for over-asking validation, only for
     * service providers (Table 9, GEN-5.2.4-06); non-empty when present (credential `[1..*]`, clause B.2.7).
     */
    @SerialName("credentials")
    val credentials: List<WrpCredential>? = null,

    /** Registry-provided unique identifier used to retrieve the intended use from the registry (Table 9). */
    @SerialName("intended_use_id")
    val intendedUseId: String? = null,

    /**
     * Credentials issued by the relying party with attestation-provider entitlements (Table 8), present only for
     * them (providesAttestations `[0..*]`, clause B.2.1).
     */
    @SerialName("provides_attestations")
    val providesAttestations: List<WrpCredential>? = null,

    /** Whether the relying party is a public sector body (Table 10). */
    @SerialName("public_body")
    val publicBody: Boolean? = null,

    /** Intermediary acting on behalf of the relying party in intermediated interactions (Table 10). */
    @SerialName("intermediary")
    val intermediary: WrpIntermediary? = null,

    /** WRPRC expiration time, at most 12 months after [iat], encoded as a Unix timestamp (Table 10; GEN-5.2.4-08). */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val exp: Instant? = null,
) {
    init {
        require(srvDescription.isNotEmpty()) { "srv_description must not be empty" } // B.2.1: [1..*]
        require(entitlements.isNotEmpty()) { "entitlements must not be empty" } // B.2.1: [1..*]
        require(purpose?.isNotEmpty() != false) { "purpose must not be empty" } // B.2.7: [1..*]
        require(credentials?.isNotEmpty() != false) { "credentials must not be empty" } // B.2.7: [1..*]
    }
}
