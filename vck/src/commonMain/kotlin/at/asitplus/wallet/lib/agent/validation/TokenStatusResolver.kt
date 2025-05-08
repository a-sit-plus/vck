package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

fun interface TokenStatusResolver {
    suspend operator fun invoke(status: Status): KmmResult<TokenStatus>
}

suspend operator fun TokenStatusResolver.invoke(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
    is SubjectCredentialStore.StoreEntry.Iso -> invoke(CredentialWrapper.Mdoc(storeEntry.issuerSigned))
    is SubjectCredentialStore.StoreEntry.SdJwt -> invoke(CredentialWrapper.SdJwt(storeEntry.sdJwt))
    is SubjectCredentialStore.StoreEntry.Vc -> invoke(CredentialWrapper.VcJws(storeEntry.vc))
}

suspend operator fun TokenStatusResolver.invoke(credentialWrapper: CredentialWrapper) = when (credentialWrapper) {
    is CredentialWrapper.Mdoc -> credentialWrapper.issuerSigned.issuerAuth.payload?.status
    is CredentialWrapper.SdJwt -> credentialWrapper.sdJwt.credentialStatus
    is CredentialWrapper.VcJws -> credentialWrapper.verifiableCredentialJws.vc.credentialStatus
}?.let {
    invoke(it)
}