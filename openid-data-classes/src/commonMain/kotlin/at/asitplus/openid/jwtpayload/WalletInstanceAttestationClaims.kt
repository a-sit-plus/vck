package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.JwtPayload

/**
 * Wallet Instance Attestation Claims (WIA) as defined by
 * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
sealed interface WalletInstanceAttestationClaims: JwtPayload {
    val walletName: String
    val walletVersion: String
    val walletSolutionCertificationInformation: String
    val clientStatus: ClientStatus
    val walletLink: String?
}