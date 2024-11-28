package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLivePayloadClaimSpecification

@ExperimentalUnsignedTypes
interface JwtPayloadClaimProvider<StatusType : Any> :
    JwtStatusPayloadClaimSpecification.ClaimProvider<StatusType>,
    JwtStatusListPayloadClaimSpecification.ClaimProvider,
    JwtTimeToLivePayloadClaimSpecification.ClaimProvider

