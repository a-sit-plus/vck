package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import io.github.aakira.napier.Napier

class VcJwsToVpJwsMappingValidator {
    operator fun invoke(
        vcJws: VerifiableCredentialJws,
        vpJws: JwsSigned<VerifiablePresentationJws>,
    ) = VcJwsToVpJwsMappingValidationSummary(
        inconsistentIssuerError = if (vpJws.payload.issuer != vcJws.subject) {
            Napier.w("vp.iss invalid: ${vpJws.payload.issuer}, but in VC is ${vcJws.subject}")
            VcJwsToVpJwsMappingValidationSummary.InconsistentIssuerError(
                vcSubject = vcJws.subject,
                vpIssuer = vpJws.payload.issuer,
            )
        } else null,
        inconsistentPublicKeyError = vpJws.header.publicKey?.let {
            if (!vpJws.header.publicKey!!.matchesIdentifier(vcJws.subject)) {
                Napier.w("vp.key invalid: ${vpJws.header.publicKey}, but in VC is ${vcJws.subject}")
                VcJwsToVpJwsMappingValidationSummary.InconsistentPublicKeyError(
                    vcSubject = vcJws.subject,
                    vpPublicKey = vpJws.header.publicKey!!,
                )
            } else null
        }
    ).also {
        if (it.isSuccess) {
            Napier.d("VC to VP mapping is valid")
        }
    }
}

