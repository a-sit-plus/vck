package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt

class InMemorySubjectCredentialStore : SubjectCredentialStore {

    private val credentials = mutableListOf<SubjectCredentialStore.StoreEntry>()

    override suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: ConstantIndex.CredentialScheme
    ) = SubjectCredentialStore.StoreEntry.Vc(vcSerialized, vc, scheme.schemaUri)
        .also { credentials += it }

    override suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: ConstantIndex.CredentialScheme
    ) = SubjectCredentialStore.StoreEntry.SdJwt(vcSerialized, vc, disclosures, scheme.schemaUri)
        .also { credentials += it }

    override suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: ConstantIndex.CredentialScheme
    ) = SubjectCredentialStore.StoreEntry.Iso(issuerSigned, scheme.schemaUri)
        .also { credentials += it }

    override suspend fun getCredentials(
        credentialSchemes: Collection<ConstantIndex.CredentialScheme>?,
    ): KmmResult<List<SubjectCredentialStore.StoreEntry>> = catching {
        credentialSchemes?.let { schemes ->
            credentials.filter {
                when (it) {
                    is SubjectCredentialStore.StoreEntry.Iso -> it.scheme in schemes
                    is SubjectCredentialStore.StoreEntry.SdJwt -> it.scheme in schemes
                    is SubjectCredentialStore.StoreEntry.Vc -> it.scheme in schemes
                }
            }.toList()
        } ?: credentials
    }
}