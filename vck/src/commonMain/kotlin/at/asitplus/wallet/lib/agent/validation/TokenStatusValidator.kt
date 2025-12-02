package at.asitplus.wallet.lib.agent.validation

import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
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
    is CredentialWrapper.SdJwt -> credentialWrapper.sdJwt.credentialStatus
    is CredentialWrapper.VcJws -> credentialWrapper.verifiableCredentialJws.vc.credentialStatus
}?.let {
    invoke(it)
} ?: TokenStatusValidationResult.Valid(null)

