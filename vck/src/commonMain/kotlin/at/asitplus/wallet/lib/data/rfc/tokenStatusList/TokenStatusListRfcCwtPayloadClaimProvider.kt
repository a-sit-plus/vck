package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.CwtPayloadClaimProvider
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.OptionalCwtStatusListTokenPayloadClaimsProvider

@ExperimentalUnsignedTypes
interface TokenStatusListRfcCwtPayloadClaimProvider<StatusType: Any> : CwtPayloadClaimProvider<StatusType>,
    OptionalCwtStatusListTokenPayloadClaimsProvider