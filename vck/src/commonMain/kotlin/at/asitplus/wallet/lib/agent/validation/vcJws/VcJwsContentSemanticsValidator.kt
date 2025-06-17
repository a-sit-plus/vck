package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

class VcJwsContentSemanticsValidator {
    operator fun invoke(vcJws: VerifiableCredentialJws) = VcJwsContentSemanticsValidationSummary(
        inconsistentIssuerError = if (vcJws.issuer != vcJws.vc.issuer) {
            Napier.w("iss invalid: ${vcJws.issuer}, expected ${vcJws.vc.issuer}")
            VcJwsContentSemanticsValidationSummary.InconsistentIssuerError(
                jwsIssuer = vcJws.issuer,
                credentialIssuer = vcJws.vc.issuer
            )
        } else null,
        inconsistentIdentifierError = if (vcJws.jwtId != vcJws.vc.id) {
            Napier.w("jti invalid: ${vcJws.jwtId}, expected ${vcJws.vc.id}")
            VcJwsContentSemanticsValidationSummary.InconsistentIdentifierError(
                jwsId = vcJws.jwtId,
                credentialId = vcJws.vc.id,
            )
        } else null,
        inconsistentSubjectError = if (vcJws.subject != vcJws.vc.credentialSubject.id) {
            Napier.w("sub invalid: ${vcJws.subject}, expected ${vcJws.vc.credentialSubject.id}")
            VcJwsContentSemanticsValidationSummary.InconsistentSubjectError(
                jwsSubject = vcJws.subject,
                credentialSubjectId = vcJws.vc.credentialSubject.id,
            )
        } else null,
        missingCredentialTypeError = if (!vcJws.vc.type.contains(VcDataModelConstants.VERIFIABLE_CREDENTIAL)) {
            Napier.w("type invalid: ${vcJws.vc.type}, expected to contain ${VcDataModelConstants.VERIFIABLE_CREDENTIAL}")
            VcJwsContentSemanticsValidationSummary.MissingCredentialTypeError(
                missingType = VcDataModelConstants.VERIFIABLE_CREDENTIAL,
                availableTypes = vcJws.vc.type
            )
        } else null,
        inconsistentNotBeforeTimeError = if (vcJws.notBefore.epochSeconds != vcJws.vc.issuanceDate.epochSeconds) {
            Napier.w("nbf invalid: ${vcJws.notBefore}, expected ${vcJws.vc.issuanceDate}")
            VcJwsContentSemanticsValidationSummary.InconsistentNotBeforeTimeError(
                jwsNotBefore = vcJws.notBefore,
                credentialIssuanceDate = vcJws.vc.issuanceDate,
            )
        } else null,
        inconsistentExpirationTimeError = if (vcJws.expiration?.epochSeconds != vcJws.vc.expirationDate?.epochSeconds) {
            Napier.w("exp invalid: ${vcJws.expiration}, expected ${vcJws.vc.expirationDate}")
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

