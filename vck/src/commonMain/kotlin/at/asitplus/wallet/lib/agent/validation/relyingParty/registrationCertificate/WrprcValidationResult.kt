package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsTyped

typealias WrprcVerifierInfoValidationResult = Map<VerifierInfo, VerifierInfoValidationResult?>

data class WrprcValidationResult(
    val verifierInfoValidationResult: WrprcVerifierInfoValidationResult,
    val requestDataValidationResult: RequestDataValidationResult
)

data class VerifierInfoValidationResult(
    val jwsTyped: JwsTyped<JwsCompact, WrpPayload>? = null,
    val signatureValid: Boolean,
    val chainValid: Boolean,
    val linkageValid: Boolean,
    val headerValid: Boolean,
    val payloadValid: Boolean,
    val statusValid: Boolean
) {
    fun isValid() =
        (this.signatureValid && this.chainValid && this.linkageValid && this.headerValid && this.payloadValid && this.statusValid)
}
