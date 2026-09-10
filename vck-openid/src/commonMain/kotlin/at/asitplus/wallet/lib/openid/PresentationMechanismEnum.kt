package at.asitplus.wallet.lib.openid

enum class PresentationMechanismEnum {
    @Deprecated("Support for Presentation Exchange has been removed from OpenID4VP; use DCQL or DeviceRequest")
    PresentationExchange,
    DCQL,
    DeviceRequest,
}
