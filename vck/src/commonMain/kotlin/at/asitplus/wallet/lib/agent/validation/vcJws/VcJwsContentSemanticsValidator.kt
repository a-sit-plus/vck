package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

class VcJwsContentSemanticsValidator {
    operator fun invoke(vcJws: VerifiableCredentialJws) = VcJwsContentSemanticsValidationSummary(
        inconsistentIssuerError = if (vcJws.issuer != vcJws.vc.issuer) {
            VcJwsContentSemanticsValidationSummary.InconsistentIssuerError(
                jwsIssuer = vcJws.issuer,
                credentialIssuer = vcJws.vc.issuer
            )
        } else null,
        inconsistentIdentifierError = if (vcJws.jwtId != vcJws.vc.id) {
            VcJwsContentSemanticsValidationSummary.InconsistentIdentifierError(
                jwsId = vcJws.jwtId,
                credentialId = vcJws.vc.id,
            )
        } else null,
        inconsistentSubjectError = if (vcJws.subject != vcJws.vc.credentialSubject.id) {
            VcJwsContentSemanticsValidationSummary.InconsistentSubjectError(
                jwsSubject = vcJws.subject,
                credentialSubjectId = vcJws.vc.credentialSubject.id,
            )
        } else null,
        missingCredentialTypeError = if (!vcJws.vc.type.contains(VcDataModelConstants.VERIFIABLE_CREDENTIAL)) {
            VcJwsContentSemanticsValidationSummary.MissingCredentialTypeError(
                missingType = VcDataModelConstants.VERIFIABLE_CREDENTIAL,
                availableTypes = vcJws.vc.type
            )
        } else null,
        inconsistentNotBeforeTimeError = if (vcJws.notBefore.epochSeconds != vcJws.vc.issuanceDate.epochSeconds) {
            VcJwsContentSemanticsValidationSummary.InconsistentNotBeforeTimeError(
                jwsNotBefore = vcJws.notBefore,
                credentialIssuanceDate = vcJws.vc.issuanceDate,
            )
        } else null,
        inconsistentExpirationTimeError = if (vcJws.expiration?.epochSeconds != vcJws.vc.expirationDate?.epochSeconds) {
            VcJwsContentSemanticsValidationSummary.InconsistentExpirationTimeError(
                jwsExpirationTime = vcJws.expiration,
                credentialExpirationDate = vcJws.vc.expirationDate,
            )
        } else null,
    ).also {
        if(it.isSuccess) {
            Napier.d("VC structure is valid")
        }
    }
}

