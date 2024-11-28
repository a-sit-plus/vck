package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusPayloadClaimSpecification

/**
 * Derivatives of [CwtStatus] are potential candidates, but a status type may also be provided by
 * a third party, so no such restriction is made.
 */
interface ReferencedCwtPayload<StatusType: Any> : CwtStatusPayloadClaimSpecification.ClaimProvider<StatusType>