package at.asitplus.openid.jwtpayload

import at.asitplus.openid.jwtpayload.claims.ClientAttestationClaims
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Deprecated("Renamed", replaceWith = ReplaceWith("WalletAttestationPayload"))
typealias WalletAttestationClaims = WalletAttestationPayload

/**
 * Wallet Instance Attestation (WIA) as defined by
 * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 * based on
 * [OID4VPI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-wallet-attestations-in-jwt-)
 * [Draft OAuth 2.0 Attestation-Based Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10)
 */
@Serializable
data class WalletAttestationPayload(
    @SerialName(IanaRegistered.ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.SUB)
    override val subject: String,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.AUD)
    override val audience: String? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.JTI)
    override val jwtId: String? = null,

    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7800.CNF)
    override val confirmationClaim: ConfirmationClaim,

    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     * EUDI TS3 REQUIRED
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_NAME)
    val walletName: String,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     * EUDI TS3 OPTIONAL
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_LINK)
    val walletLink: String? = null,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. version of the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_VERSION)
    val walletVersion: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. information about the certification achieved by the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_SOLUTION_CERTIFICATION_INFORMATION)
    val walletSolutionCertificationInformation: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED.
     * status list reference for the Wallet Instance and the time until which the Wallet Provider
     * commits to maintaining the referenced status.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.CLIENT_STATUS)
    val clientStatus: ClientStatus,
) : ClientAttestationClaims {
}