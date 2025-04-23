package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant

class VerifiableCredentialJwsStructureValidator {
    fun validate(vcJws: VerifiableCredentialJws): ValidationSummary {
        return ValidationSummary(
            inconsistentIssuerError = if (vcJws.issuer != vcJws.vc.issuer) {
                Napier.w("iss invalid: ${vcJws.issuer}, expected ${vcJws.vc.issuer}")
                InconsistentIssuerError(
                    jwsIssuer = vcJws.issuer,
                    credentialIssuer = vcJws.vc.issuer
                )
            } else null,
            inconsistentIdentifierError = if (vcJws.jwtId != vcJws.vc.id) {
                Napier.w("jti invalid: ${vcJws.jwtId}, expected ${vcJws.vc.id}")
                InconsistentIdentifierError(
                    jwsId = vcJws.jwtId,
                    credentialId = vcJws.vc.id,
                )
            } else null,
            inconsistentSubjectError = if (vcJws.subject != vcJws.vc.credentialSubject.id) {
                Napier.w("sub invalid: ${vcJws.subject}, expected ${vcJws.vc.credentialSubject.id}")
                InconsistentSubjectError(
                    jwsSubject = vcJws.subject,
                    credentialSubjectId = vcJws.vc.credentialSubject.id,
                )
            } else null,
            missingCredentialTypeError = if (!vcJws.vc.type.contains(VcDataModelConstants.VERIFIABLE_CREDENTIAL)) {
                Napier.w("type invalid: ${vcJws.vc.type}, expected to contain ${VcDataModelConstants.VERIFIABLE_CREDENTIAL}")
                MissingCredentialTypeError(
                    missingType = VcDataModelConstants.VERIFIABLE_CREDENTIAL,
                    availableTypes = vcJws.vc.type
                )
            } else null,
            inconsistentNotBeforeTimeError = if (vcJws.notBefore.epochSeconds != vcJws.vc.issuanceDate.epochSeconds) {
                Napier.w("nbf invalid: ${vcJws.notBefore}, expected ${vcJws.vc.issuanceDate}")
                InconsistentNotBeforeTimeError(
                    jwsNotBefore = vcJws.notBefore,
                    credentialIssuanceDate = vcJws.vc.issuanceDate,
                )
            } else null,
            inconsistentExpirationTimeError = if (vcJws.expiration?.epochSeconds != vcJws.vc.expirationDate?.epochSeconds) {
                Napier.w("exp invalid: ${vcJws.expiration}, expected ${vcJws.vc.expirationDate}")
                InconsistentExpirationTimeError(
                    jwsExpirationTime = vcJws.expiration,
                    credentialExpirationDate = vcJws.vc.expirationDate,
                )
            } else null,
        ).also {
            if(!it.containsErrors) {
                Napier.d("VC structure is valid")
            }
        }
    }

    data class ValidationSummary(
        val inconsistentIssuerError: InconsistentIssuerError?,
        val inconsistentIdentifierError: InconsistentIdentifierError?,
        val inconsistentSubjectError: InconsistentSubjectError?,
        val missingCredentialTypeError: MissingCredentialTypeError?,
        val inconsistentNotBeforeTimeError: InconsistentNotBeforeTimeError?,
        val inconsistentExpirationTimeError: InconsistentExpirationTimeError?,
    ) {
        val containsErrors = listOf(
            inconsistentIssuerError != null,
            inconsistentIdentifierError != null,
            inconsistentSubjectError != null,
            missingCredentialTypeError != null,
            inconsistentNotBeforeTimeError != null,
            inconsistentExpirationTimeError != null,
        ).any { it }
    }

    data class InconsistentIssuerError(
        val jwsIssuer: String,
        val credentialIssuer: String,
    )

    data class InconsistentIdentifierError(
        val jwsId: String,
        val credentialId: String,
    )

    data class InconsistentSubjectError(
        val jwsSubject: String,
        val credentialSubjectId: String,
    )

    data class MissingCredentialTypeError(
        val missingType: String,
        val availableTypes: Collection<String>,
    )

    data class InconsistentNotBeforeTimeError(
        val jwsNotBefore: Instant,
        val credentialIssuanceDate: Instant,
    )

    data class InconsistentExpirationTimeError(
        val jwsExpirationTime: Instant?,
        val credentialExpirationDate: Instant?,
    )
}