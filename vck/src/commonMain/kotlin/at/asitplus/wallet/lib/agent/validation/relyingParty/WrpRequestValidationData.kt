package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.data.CredentialPresentationRequest

data class WrpRequestValidationData(
    val clientId: String? = null,
    val certificateChain: CertificateChain? = null,
    val verifierInfo: NonEmptyList<VerifierInfo>? = null,
    val request: CredentialPresentationRequest? = null,
)
