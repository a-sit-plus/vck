package at.asitplus.wallet.lib.data

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import kotlin.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * SD-JWT representation of a [VerifiableCredential].
 * According to
 * [SD-JWT-based Verifiable Credentials (SD-JWT VC), Draft 10](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
 * and
 * [Selective Disclosure for JSON Web Tokens](https://www.rfc-editor.org/rfc/rfc9901.html)
 */
@Serializable
data class VerifiableCredentialSdJwt(
    /**
     * OPTIONAL. The identifier of the Subject of the Verifiable Credential. The Issuer MAY use it to provide the
     * Subject identifier known by the Issuer. There is no requirement for a binding to exist between [subject] and
     * [confirmationClaim] claims.
     */
    @SerialName("sub")
    val subject: String? = null,

    /**
     * OPTIONAL. The time before which the Verifiable Credential MUST NOT be accepted before validating.
     * See [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) for more information.
     */
    @SerialName("nbf")
    @Serializable(with = NullableInstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * OPTIONAL. As defined in Section 4.1.1 of [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) this claim
     * explicitly indicates the Issuer of the Verifiable Credential when it is not conveyed by other means
     * (e.g., the subject of the end-entity certificate of an `x5c` header).
     */
    @SerialName("iss")
    val issuer: String? = null,

    /**
     * OPTIONAL. The expiry time of the Verifiable Credential after which the Verifiable Credential is no longer valid.
     * See [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) for more information.
     */
    @SerialName("exp")
    @Serializable(with = NullableInstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * OPTIONAL. The time of issuance of the Verifiable Credential.
     * See [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519) for more information.
     */
    @SerialName("iat")
    @Serializable(with = NullableInstantLongSerializer::class)
    val issuedAt: Instant? = null,

    @SerialName("jti")
    val jwtId: String? = null,

    @SerialName("_sd")
    val disclosureDigests: Collection<String>? = null,

    /**
     * REQUIRED. The type of the Verifiable Credential, e.g., `https://credentials.example.com/identity_credential`.
     * This specification defines the JWT claim `vct` (for verifiable credential type).
     * The `vct` value MUST be a case-sensitive StringOrURI (see
     * [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519)) value serving as an identifier for the type of the
     * SD-JWT VC. The `vct` value MUST be a Collision-Resistant Name as defined in Section 2 of
     * [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515).
     */
    @SerialName("vct")
    val verifiableCredentialType: String,

    /**
     * The value MUST be an "integrity metadata" string as defined in Section 3 of
     * [W3C.SRI](https://www.w3.org/TR/sri/). A Consumer of the respective documents MUST verify the integrity of the
     * retrieved document as defined in Section 3.3.5 of [W3C.SRI](https://www.w3.org/TR/sri/).
     */
    @SerialName("vct#integrity")
    val verifiableCredentialTypeIntegrity: String? = null,

    /**
     * OPTIONAL. The information on how to read the status of the Verifiable Credential.
     * By including a `status` claim in a Referenced Token, the Issuer is referencing a mechanism to retrieve status
     * information about this Referenced Token. This specification defines one possible member of the `status` object,
     * called `status_list`. Other members of the `status` object may be defined by other specifications. This is
     * analogous to `cnf` claim in Section 3.1 of [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800) in which
     * different authenticity confirmation methods can be included.
     *
     * See [Token Status List](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12).
     */
    @SerialName("status")
    @Serializable(with = RevocationListInfo.StatusSurrogateSerializer::class)
    val statusElement: RevocationListInfo? = null,

    /**
     * The claim `_sd_alg` indicates the hash algorithm used by the Issuer to generate the digests as described in
     * Section 4.2. When used, this claim MUST appear at the top level of the SD-JWT payload. It MUST NOT be used in
     * any object nested within the payload. If the `_sd_alg` claim is not present at the top level, a default value of
     * `sha-256` MUST be used.
     */
    @SerialName("_sd_alg")
    val selectiveDisclosureAlgorithm: String? = null,

    /**
     * OPTIONAL unless cryptographic Key Binding is to be supported, in which case it is REQUIRED.
     * Contains the confirmation method identifying the proof of possession key as defined in
     * [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800).
     * It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of
     * [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800).
     * For proof of cryptographic Key Binding, the KB-JWT in the presentation of the SD-JWT MUST be secured by
     * the key identified in this claim.
     */
    @SerialName("cnf")
    val confirmationClaim: ConfirmationClaim? = null,
) {

    /**
     * OPTIONAL. The information on how to read the status of the Verifiable Credential.
     * By including a `status` claim in a Referenced Token, the Issuer is referencing a mechanism to retrieve status
     * information about this Referenced Token. This specification defines one possible member of the `status` object,
     * called `status_list`. Other members of the `status` object may be defined by other specifications. This is
     * analogous to `cnf` claim in Section 3.1 of [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800) in which
     * different authenticity confirmation methods can be included.
     *
     * See [Token Status List](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12).
     */
    @Deprecated(message = "Replaced by statusElement", replaceWith = ReplaceWith("statusElement"))
    val credentialStatus: RevocationListInfo?
        get() = statusElement

}