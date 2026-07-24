package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtClaimNames.UnregisteredClaims
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Wallet Instance Attestation (WIA) as defined by
 * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
@Deprecated("Will move into VCK next release")
@Serializable
data class WalletAttestationPopPayload(
    @SerialName(IanaRegistered.ClaimNames.RFC7519.SUB)
    override val subject: String? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.AUD)
    override val audience: String,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,
    @SerialName(IanaRegistered.ClaimNames.RFC7519.JTI)
    override val jwtId: String,
    @SerialName(UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)
    override val challenge: String? = null,
    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     * EUDI TS3 REQUIRED
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_NAME)
    override val walletName: String,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     * EUDI TS3 OPTIONAL
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_LINK)
    override val walletLink: String? = null,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. version of the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_VERSION)
    override val walletVersion: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED. information about the certification achieved by the Wallet Solution.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_SOLUTION_CERTIFICATION_INFORMATION)
    override val walletSolutionCertificationInformation: String,

    /**
     * EUDI TS3 WUA 1.5: REQUIRED.
     * status list reference for the Wallet Instance and the time until which the Wallet Provider
     * commits to maintaining the referenced status.
     */
    @SerialName(UnregisteredClaims.EudiTs3Claims.CLIENT_STATUS)
    override val clientStatus: ClientStatus,

    ) : ClientAttestationClaims.ProofOfPossession, WalletInstanceAttestationClaims {
}