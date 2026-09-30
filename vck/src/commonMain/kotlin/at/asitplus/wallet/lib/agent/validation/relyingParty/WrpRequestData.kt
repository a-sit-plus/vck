package at.asitplus.wallet.lib.agent.validation.relyingParty

import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest

data class WrpRequestData(
    val clientId: String? = null,
    val accessCertificate: WrpAccessCertificate,
    val registrationCertificate: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>>
)

sealed interface WrpRegistrationCertificate {
    val payload: WrpPayload

    data class WrpJwtRegistrationCertificate(
        val jwsTyped: JwsTyped<JwsCompact, WrpPayload>,
        override val payload: WrpPayload = jwsTyped.payload
    ) : WrpRegistrationCertificate

    data class WrpCwtRegistrationCertificate(
        val cose: CoseSigned<ByteArray>,
        override val payload: WrpPayload
    ) : WrpRegistrationCertificate
}

data class WrpAccessCertificate(
    val certificateChain: CertificateChain? = null,
)