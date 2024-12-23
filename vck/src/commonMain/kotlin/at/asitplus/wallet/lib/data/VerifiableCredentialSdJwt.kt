package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * SD-JWT representation of a [VerifiableCredential].
 * According to
 * [SD-JWT-based Verifiable Credentials (SD-JWT VC), Draft 05](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html)
 * and
 * [Selective Disclosure for JWTs (SD-JWT), Draft 13](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html)
 */
@Serializable
data class VerifiableCredentialSdJwt(
    /**
     * OPTIONAL. The identifier of the Subject of the Verifiable Credential. The Issuer MAY use it to provide the
     * Subject identifier known by the Issuer.
     * There is no requirement for a binding to exist between `sub` and `cnf` claims.
     */
    @SerialName("sub")
    val subject: String? = null,

    /**
     * OPTIONAL. The time before which the Verifiable Credential MUST NOT be accepted before validating.
     * See RFC7519 for more information.
     */
    @SerialName("nbf")
    @Serializable(with = NullableInstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * REQUIRED. The Issuer of the Verifiable Credential. The value of iss MUST be a URI.
     * See RFC7519 for more information.
     */
    @SerialName("iss")
    val issuer: String,

    /**
     * OPTIONAL. The expiry time of the Verifiable Credential after which the Verifiable Credential is no longer valid.
     * See RFC7519 for more information.
     */
    @SerialName("exp")
    @Serializable(with = NullableInstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * OPTIONAL. The time of issuance of the Verifiable Credential.
     * See RFC7519 for more information.
     */
    @SerialName("iat")
    @Serializable(with = NullableInstantLongSerializer::class)
    val issuedAt: Instant? = null,

    @SerialName("jti")
    val jwtId: String? = null,

    @SerialName("_sd")
    val disclosureDigests: Collection<String>? = null,

    /**
     * REQUIRED. This specification defines the JWT claim `vct` (for verifiable credential type).
     * The vct value MUST be a case-sensitive StringOrURI (see RFC7519) value serving as an identifier for the type
     * of the SD-JWT VC. The vct value MUST be a Collision-Resistant Name as defined in Section 2 of RFC7515.
     */
    @SerialName("vct")
    val verifiableCredentialType: String,

    /**
     * https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-claim
     * OPTIONAL.
     * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism
     * to retrieve status information about this Referenced Token. The claim contains members used
     * to reference to a Status List Token as defined in this specification. Other members of the
     * "status" object may be defined by other specifications. This is analogous to "cnf" claim in
     * Section 3.1 of [RFC7800] in which different authenticity confirmation methods can be
     * included.
     */
    @SerialName("status")
    val credentialStatus: Status? = null,

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
     * Contains the confirmation method identifying the proof of possession key as defined in RFC7800.
     * It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of RFC7800.
     * For proof of cryptographic Key Binding, the Key Binding JWT in the presentation of the SD-JWT MUST be signed by
     * the key identified in this claim.
     */
    @SerialName("cnf")
    val confirmationClaim: ConfirmationClaim? = null,
) {

    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            vckJsonSerializer.decodeFromString<VerifiableCredentialSdJwt>(it)
        }.wrap()
    }

}