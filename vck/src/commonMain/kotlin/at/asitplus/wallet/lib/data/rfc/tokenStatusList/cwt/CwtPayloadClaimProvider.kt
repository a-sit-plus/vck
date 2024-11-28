package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLivePayloadClaimSpecification

interface CwtPayloadClaimProvider<Status: Any> :
    CwtStatusPayloadClaimSpecification.ClaimProvider<Status>,
    CwtStatusListPayloadClaimSpecification.ClaimProvider,
    CwtTimeToLivePayloadClaimSpecification.ClaimProvider