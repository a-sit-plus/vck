package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusPayloadClaimSpecification

@Suppress("UNUSED")
interface ReferencedCwtPayload<Status: Any> : CwtStatusPayloadClaimSpecification.ClaimProvider<Status>