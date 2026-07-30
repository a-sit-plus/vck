package at.asitplus.openid.jwtpayload.claims

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered
import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlinx.serialization.SerialName


/**
 * [RFC7800](https://datatracker.ietf.org/doc/html/rfc7800)
 * describes how to declare in a JSON Web Token (JWT)
 * that the presenter of the JWT possesses a particular proof-of-
 * possession key and how the recipient can cryptographically confirm
 * proof of possession of the key by the presenter.
 *
 * Not to be confused with [DemonstratingProofOfPossessionClaims]
 */
interface ProofOfPossessionClaims : JwtPayload {
    @SerialName(IanaRegistered.ClaimNames.RFC7800.CNF)
    val confirmationClaim: ConfirmationClaim
}