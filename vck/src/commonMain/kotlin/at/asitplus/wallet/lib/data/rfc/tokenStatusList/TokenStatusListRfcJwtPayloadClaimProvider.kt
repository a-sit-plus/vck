package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.JwtPayloadClaimProvider
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.OptionalJwtStatusListTokenPayloadClaimsProvider

@ExperimentalUnsignedTypes
interface TokenStatusListRfcJwtPayloadClaimProvider<StatusType: Any> : JwtPayloadClaimProvider<StatusType>,
        OptionalJwtStatusListTokenPayloadClaimsProvider

