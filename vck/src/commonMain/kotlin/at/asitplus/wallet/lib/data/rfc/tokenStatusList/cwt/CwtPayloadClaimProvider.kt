package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLivePayloadClaimSpecification

@ExperimentalUnsignedTypes
interface CwtPayloadClaimProvider<StatusType : Any> :
    CwtStatusPayloadClaimSpecification.ClaimProvider<StatusType>,
    CwtStatusListPayloadClaimSpecification.ClaimProvider,
    CwtTimeToLivePayloadClaimSpecification.ClaimProvider