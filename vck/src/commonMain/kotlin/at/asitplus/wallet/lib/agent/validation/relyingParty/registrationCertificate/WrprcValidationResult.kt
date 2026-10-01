package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate

/**
 * Result of [WrprcValidator].
 *
 * A failed [KmmResult] marks the registration certificate or the credential request as invalid and carries the cause,
 * e.g. a certificate chain that could not be parsed or a credential request that could not be checked.
 */
data class WrprcValidationResult(
    val certificateValidationResults: Map<WrpRegistrationCertificate, KmmResult<WrpRegistrationCertificateValidation>>,
    val requestDataValidationResults: RequestDataValidationResults,
) {
    @Deprecated(
        "Use certificateValidationResults, which carries the cause of a failed validation",
        ReplaceWith("certificateValidationResults")
    )
    val certificateValidation: Map<WrpRegistrationCertificate, WrpRegistrationCertificateValidation?>
        get() = certificateValidationResults.mapValues { it.value.getOrNull() }

    /** Omits credential requests that could not be validated. */
    @Deprecated(
        "Use requestDataValidationResults, which carries the cause of a failed validation",
        ReplaceWith("requestDataValidationResults")
    )
    val requestDataValidation: RequestDataValidation
        get() = requestDataValidationResults.mapNotNull { (request, result) -> result.getOrNull()?.let { request to it } }

    companion object {
        @Deprecated(
            "Use the constructor taking results, which carry the cause of a failed validation",
            ReplaceWith("WrprcValidationResult(certificateValidationResults, requestDataValidationResults)")
        )
        operator fun invoke(
            certificateValidation: Map<WrpRegistrationCertificate, WrpRegistrationCertificateValidation?>,
            requestDataValidation: RequestDataValidation,
        ) = WrprcValidationResult(
            certificateValidationResults = certificateValidation.mapValues { (certificate, validation) ->
                validation?.let { KmmResult.success(it) }
                    ?: KmmResult.failure(IllegalArgumentException("$certificate could not be validated"))
            },
            requestDataValidationResults = requestDataValidation.map { (request, validity) ->
                request to KmmResult.success(validity)
            },
        )
    }
}


data class WrpRegistrationCertificateValidation(
    val validHeader: Boolean,
    val validSignature: Boolean,
    val validChain: Boolean,
    val validPayload: Boolean,
    val validLinkage: Boolean,
    val validStatusList: Boolean
) {
    fun isValid() = validHeader && validSignature && validChain && validPayload && validLinkage && validStatusList
}
