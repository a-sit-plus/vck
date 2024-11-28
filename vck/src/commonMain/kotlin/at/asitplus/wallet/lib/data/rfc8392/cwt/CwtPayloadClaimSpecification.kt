package at.asitplus.wallet.lib.data.rfc8392.cwt

interface CwtPayloadClaimSpecification {
    companion object

    val claimName: CwtClaimName
    val claimKey: CwtClaimKey

    fun toNameWithKeyString() = "$claimName ($claimKey)"
}