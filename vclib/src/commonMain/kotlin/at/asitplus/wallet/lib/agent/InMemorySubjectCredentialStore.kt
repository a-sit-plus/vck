package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws

class InMemorySubjectCredentialStore : SubjectCredentialStore {

    private val credentials = mutableListOf<SubjectCredentialStore.StoreEntry>()
    private val attachments = mutableListOf<SubjectCredentialStore.AttachmentEntry>()

    override suspend fun storeCredential(vc: VerifiableCredentialJws, vcSerialized: String) {
        credentials += SubjectCredentialStore.StoreEntry(vcSerialized, vc)
    }

    override suspend fun storeAttachment(name: String, data: ByteArray, vcId: String) {
        attachments += SubjectCredentialStore.AttachmentEntry(name, data, vcId)
    }

    override suspend fun getCredentials(
        requiredAttributeTypes: Collection<String>?,
    ) = KmmResult.success(
        credentials.filter {
            requiredAttributeTypes?.let { types ->
                it.vc.vc.type.any { it in types }
            } ?: true
        }
    )

    override suspend fun getAttachment(name: String) =
        attachments.firstOrNull { it.name == name }?.data?.let { KmmResult.success(it) }
            ?: KmmResult.failure(NullPointerException("Attachment not found"))

    override suspend fun getAttachment(name: String, vcId: String) =
        attachments.firstOrNull { it.name == name && it.vcId == vcId }?.data?.let { KmmResult.success(it) }
            ?: KmmResult.failure(NullPointerException("Attachment not found"))

}