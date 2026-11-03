package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.CredentialScheme

class InMemorySubjectCredentialStore : SubjectCredentialStore {

    private val credentials = mutableListOf<SubjectCredentialStore.StoreEntry>()

    override suspend fun storeCredential(
        entry: SubjectCredentialStore.StoreEntry,
    ): KmmResult<SubjectCredentialStore.StoreEntry> = catching {
        entry.also { credentials += it }
    }

    override suspend fun getCredentials(
        credentialSchemes: Collection<CredentialScheme>?,
    ): KmmResult<List<SubjectCredentialStore.StoreEntry>> = catching {
        credentialSchemes?.let { schemes ->
            credentials.filter { it.resolveScheme() in schemes }.toList()
        } ?: credentials
    }
}
