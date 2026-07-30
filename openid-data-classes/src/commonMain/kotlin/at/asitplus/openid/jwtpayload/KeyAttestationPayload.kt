package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.EudiWalletInfo
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims.DraftIetfOauthStatusList
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims.EudiTs3Claims
import at.asitplus.signum.indispensable.josef.JwtPayload
import at.asitplus.signum.indispensable.josef.KeyStorageStatus
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/**
 * Content of a Key Attestation in JWT format, according to
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#keyattestation-jwt)
 */
@Serializable
data class KeyAttestationPayload(
    @SerialName(ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,
    @SerialName(ClaimNames.RFC7519.SUB)
    override val subject: String,
    @SerialName(ClaimNames.RFC7519.AUD)
    override val audience: String? = null,
    @SerialName(ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName(ClaimNames.RFC7519.JTI)
    override val jwtId: String? = null,
    /**
     * Integer for the time at which the key attestation was issued using the syntax defined in RFC7519.
     */
    @SerialName(ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,

    /**
     * Integer for the time at which the key attestation and the key(s) it is attesting expire, using the syntax
     * defined in RFC7519. MUST be present if the attestation is used with the JWT proof type.
     */
    @SerialName(ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,

    /**
     * Optional. String that represents a nonce provided by the Issuer to prove that a key attestation was freshly
     * generated.
     */
    @SerialName(ClaimNames.RFC9449.NONCE)
    val nonce: String? = null,

    /**
     * Data class containing information for instance/unit attestation
     * which are not part of the OID4VCI specification.
     * See https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
     */
    @Deprecated("TS3 WUA 1.5 removed eudi_wallet_info from Key Attestations.")
    @SerialName(EudiTs3Claims.WALLET_INFO)
    val eudiWalletInfo: EudiWalletInfo? = null,

    /**
     * Array of attested keys from the same key storage component using the syntax of JWK as defined in RFC7517.
     */
    @SerialName(EudiTs3Claims.ATTESTED_KEYS)
    val attestedKeys: Collection<JsonWebKey>,

    /**
     * Optional. Array of case sensitive strings that assert the attack potential resistance of the key storage
     * component and its keys attested in the attested_keys parameter. This specification defines initial values in
     * Appendix D.2.
     */
    @SerialName(EudiTs3Claims.KEY_STORAGE)
    val keyStorage: Collection<String>? = null,

    /**
     * Optional. Array of case sensitive strings that assert the attack potential resistance of the user authentication
     * methods allowed to access the private keys from the [attestedKeys] parameter.
     * This specification defines initial values in Appendix D.2.
     */
    @SerialName(EudiTs3Claims.USER_AUTHENTICATION)
    val userAuthentication: Collection<String>? = null,

    /**
     * Optional. A String that contains a URL that links to the certification of the key storage component.
     */
    @SerialName(EudiTs3Claims.CERTIFICATION)
    val certification: String? = null,

    /**
     * EUDI TS3 WUA 1.5: status list reference for the attested key storage and the time until which the Wallet
     * Provider commits to maintaining the referenced status.
     */
    @SerialName(EudiTs3Claims.KEY_STORAGE_STATUS)
    val keyStorageStatus: KeyStorageStatus? = null,

    /**
     * Optional. JSON Object representing the supported revocation check mechanisms, such as the one defined in
     * ietf-oauth-status-list.
     */
    @Deprecated("TS3 WUA 1.5 replaced top-level status with key_storage_status.")
    @SerialName(DraftIetfOauthStatusList.STATUS)
    val status: JsonObject? = null,
) : JwtPayload