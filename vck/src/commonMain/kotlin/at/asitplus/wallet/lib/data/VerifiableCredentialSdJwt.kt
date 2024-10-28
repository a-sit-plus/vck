package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * SD-JWT representation of a [VerifiableCredential].
 * According to "SD-JWT-based Verifiable Credentials (SD-JWT VC), Draft 03"
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
     * OPTIONAL. The information on how to read the status of the Verifiable Credential.
     * See (I-D.looker-oauth-jwt-cwt-status-list) for more information.
     */
    @SerialName("status")
    // TODO Implement correct draft: draft-ietf-oauth-status-list-05
    val credentialStatus: CredentialStatus? = null,

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
    // Should be [ConfirmationClaim], but was [JsonWebKey] in our previous implementation...
    val cnfElement: JsonElement? = null,
) {

    @Deprecated("Use confirmationClaim", replaceWith = ReplaceWith("confirmationClaim.jsonWebKey"))
    val confirmationKey: JsonWebKey?
        get() = cnfElement?.let {
            runCatching { vckJsonSerializer.decodeFromJsonElement<JsonWebKey>(it) }.getOrNull()
        }

    val confirmationClaim: ConfirmationClaim?
        get() = cnfElement?.let {
            runCatching { vckJsonSerializer.decodeFromJsonElement<ConfirmationClaim>(it) }.getOrNull()
        }

    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            vckJsonSerializer.decodeFromString<VerifiableCredentialSdJwt>(it)
        }.wrap()
    }

}