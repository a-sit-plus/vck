package at.asitplus.wallet.lib.agent.validation.mdoc

data class MdocTimelinessValidationDetails(
    val msoTimelinessValidationSummary: MobileSecurityObjectTimelinessValidationSummary?,
) {
    val isSuccess: Boolean
        get() = msoTimelinessValidationSummary?.isSuccess != false
}