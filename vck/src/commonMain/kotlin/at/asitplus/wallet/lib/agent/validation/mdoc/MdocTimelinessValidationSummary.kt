package at.asitplus.wallet.lib.agent.validation.mdoc

data class MdocTimelinessValidationSummary(
    val msoTimelinessValidationSummary: MobileSecurityObjectTimelinessValidationSummary?,
) {
    val isSuccess: Boolean
        get() = msoTimelinessValidationSummary?.isSuccess != false
}