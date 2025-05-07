package at.asitplus.wallet.lib.agent.validation

import kotlinx.datetime.Instant

data class VcJwsContentSemanticsValidationSummary(
    val inconsistentIssuerError: InconsistentIssuerError?,
    val inconsistentIdentifierError: InconsistentIdentifierError?,
    val inconsistentSubjectError: InconsistentSubjectError?,
    val missingCredentialTypeError: MissingCredentialTypeError?,
    val inconsistentNotBeforeTimeError: InconsistentNotBeforeTimeError?,
    val inconsistentExpirationTimeError: InconsistentExpirationTimeError?,
) {
    val isSuccess = listOf(
        inconsistentIssuerError != null,
        inconsistentIdentifierError != null,
        inconsistentSubjectError != null,
        missingCredentialTypeError != null,
        inconsistentNotBeforeTimeError != null,
        inconsistentExpirationTimeError != null,
    ).all { it }

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