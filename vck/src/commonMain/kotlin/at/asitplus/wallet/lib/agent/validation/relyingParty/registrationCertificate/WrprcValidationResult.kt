package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.jvm.JvmOverloads

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

    /**
     * Maps credential requests that could not be validated to an invalid credential type without attributes, so that
     * [RequestDataValidity.isValid] is `false` for them. Checking only the attributes of such a request finds none.
     */
    @Deprecated(
        "Use requestDataValidationResults, which carries the cause of a failed validation",
        ReplaceWith("requestDataValidationResults")
    )
    val requestDataValidation: RequestDataValidation
        get() = requestDataValidationResults.map { (request, result) ->
            request to result.getOrElse {
                RequestDataValidity(credentialTypeValidity = false, credentialAttributesValidity = emptyList())
            }
        }

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


data class WrpRegistrationCertificateValidation @JvmOverloads constructor(
    val validHeader: Boolean,
    val validSignature: Boolean,
    val validChain: Boolean,
    val validPayload: Boolean,
    val validLinkage: Boolean,
    val validStatusList: Boolean,
    /**
     * Status of the registration certificate from its status list, e.g. to tell a revoked or suspended certificate
     * apart from one whose status could not be obtained, which is a failure.
     */
    val tokenStatus: KmmResult<TokenStatus> =
        KmmResult.success(if (validStatusList) TokenStatus.Valid else TokenStatus.Invalid),
) {
    fun isValid() = validHeader && validSignature && validChain && validPayload && validLinkage && validStatusList
}
