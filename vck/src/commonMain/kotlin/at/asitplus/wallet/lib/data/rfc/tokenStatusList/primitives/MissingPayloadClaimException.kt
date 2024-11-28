package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

class MissingPayloadClaimException(val claimName: String) : IllegalStateException("Missing payload claim `$claimName`")
