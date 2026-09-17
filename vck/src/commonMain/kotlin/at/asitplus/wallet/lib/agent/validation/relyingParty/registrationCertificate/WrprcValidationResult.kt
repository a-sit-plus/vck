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
    val validLinkage: Boolean,
    val validStatusList: Boolean
) {
    fun isValid() = validStatusList && validLinkage
}
