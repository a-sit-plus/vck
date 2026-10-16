@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate

import at.asitplus.signum.indispensable.pki.X509Certificate

@Deprecated("Validate relying parties with at.asitplus.wallet.lib.validation.RelyingPartyValidator. To be removed in the next major release.")
data class WrpacValidationResult(
    val chain: List<X509Certificate>,
    val identifierResult: WrpacIdentifier?,
    val validLinkage: Boolean
)
