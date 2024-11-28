package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.JwtStatusMechanismProvider

/**
 * Derivatives of [JwtStatusMechanismProvider] are potential candidates, but a status type may also be provided by
 * a third party, so no such restriction is made.
 */
interface ReferencedJwtPayload : JwtStatusPayloadClaimSpecification.ClaimProvider
