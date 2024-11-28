package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.JwtPayloadClaimProvider
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.OptionalJwtStatusListTokenPayloadClaimsProvider

interface TokenStatusListRfcJwtPayloadClaimProvider : JwtPayloadClaimProvider,
        OptionalJwtStatusListTokenPayloadClaimsProvider

