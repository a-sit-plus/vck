package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.signum.indispensable.pki.Certificate

data class WrpacValidationResult(
    val chain: List<Certificate>,
    val identifierResult: WrpacIdentifier?,
    val validLinkage: Boolean
)
