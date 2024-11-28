package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLivePayloadClaimSpecification

interface JwtPayloadClaimProvider :
    JwtStatusPayloadClaimSpecification.ClaimProvider,
    JwtStatusListPayloadClaimSpecification.ClaimProvider,
    JwtTimeToLivePayloadClaimSpecification.ClaimProvider

