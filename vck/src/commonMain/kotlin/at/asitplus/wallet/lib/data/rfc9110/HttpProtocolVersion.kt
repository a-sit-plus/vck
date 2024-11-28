package at.asitplus.wallet.lib.data.rfc9110

data class HttpProtocolVersion(
    val majorVersion: ULong,
    val minorVersion: ULong = 0u,
)