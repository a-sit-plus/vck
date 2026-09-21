package at.asitplus.wallet.lib.agent.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult

fun interface TokenStatusValidator {
    suspend operator fun invoke(status: RevocationListInfo): TokenStatusValidationResult
}

fun TokenStatusResolver.toTokenStatusValidator(
    acceptedTokenStatuses: Set<TokenStatus> = setOf(TokenStatus.Valid)
) = TokenStatusValidator {
    val result = invoke(revocationListInfo = it)
    val tokenStatus = result.getOrElse {
        return@TokenStatusValidator TokenStatusValidationResult.Rejected(it)
    }
    if (tokenStatus in acceptedTokenStatuses) {
        TokenStatusValidationResult.Valid(tokenStatus)
    } else {
        TokenStatusValidationResult.Invalid(tokenStatus)
    }
}

/**
 * Validates every advertised status mechanism. Invalid status takes precedence over resolution failures;
 * otherwise, all mechanisms must resolve successfully and agree.
 */
suspend fun TokenStatusValidator.validate(status: TokenStatusInfo): TokenStatusValidationResult {
    val results = status.mechanisms.map { invoke(it) }
    results.filterIsInstance<TokenStatusValidationResult.Invalid>().firstOrNull()?.let { return it }
    results.filterIsInstance<TokenStatusValidationResult.Rejected>().firstOrNull()?.let { return it }

    val validResults = results.filterIsInstance<TokenStatusValidationResult.Valid>()
    return if (validResults.map { it.tokenStatus }.distinct().size == 1) {
        validResults.first()
    } else {
        TokenStatusValidationResult.Rejected(
            IllegalArgumentException("Token status mechanisms returned conflicting results")
        )
    }
}

suspend operator fun TokenStatusValidator.invoke(issuerSigned: IssuerSigned) = invoke(
    CredentialWrapper.Mdoc(issuerSigned)
)

suspend operator fun TokenStatusValidator.invoke(sdJwt: VerifiableCredentialSdJwt) = invoke(
    CredentialWrapper.SdJwt(sdJwt)
)

suspend operator fun TokenStatusValidator.invoke(vcJws: VerifiableCredentialJws) = invoke(
    CredentialWrapper.VcJws(vcJws)
)

suspend operator fun TokenStatusValidator.invoke(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
    is SubjectCredentialStore.StoreEntry.Iso -> invoke(CredentialWrapper.Mdoc(storeEntry.issuerSigned))
    is SubjectCredentialStore.StoreEntry.SdJwt -> invoke(CredentialWrapper.SdJwt(storeEntry.sdJwt))
    is SubjectCredentialStore.StoreEntry.Vc -> invoke(CredentialWrapper.VcJws(storeEntry.vc))
}

suspend operator fun TokenStatusValidator.invoke(credentialWrapper: CredentialWrapper) = when (credentialWrapper) {
    is CredentialWrapper.Mdoc -> credentialWrapper.issuerSigned.issuerAuth.payload?.status
    is CredentialWrapper.SdJwt -> credentialWrapper.sdJwt.statusElement
    is CredentialWrapper.VcJws -> credentialWrapper.verifiableCredentialJws.vc.credentialStatus
}?.let {
    val statusInfo = TokenStatusInfo.from(it)
    if (statusInfo.mechanisms.size > 1) {
        validate(statusInfo)
    } else {
        invoke(it)
    }
} ?: TokenStatusValidationResult.Valid(null)
