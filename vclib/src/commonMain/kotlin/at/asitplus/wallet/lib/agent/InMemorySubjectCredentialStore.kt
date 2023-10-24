package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.IssuerSigned

class InMemorySubjectCredentialStore : SubjectCredentialStore {

    private val credentials = mutableListOf<SubjectCredentialStore.StoreEntry>()
    private val attachments = mutableListOf<SubjectCredentialStore.AttachmentEntry>()

    override suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: ConstantIndex.CredentialScheme
    ) {
        credentials += SubjectCredentialStore.StoreEntry.Vc(vcSerialized, vc, scheme)
    }

    override suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: ConstantIndex.CredentialScheme
    ) {
        credentials += SubjectCredentialStore.StoreEntry.SdJwt(vcSerialized, vc, disclosures, scheme)
    }

    override suspend fun storeCredential(issuerSigned: IssuerSigned, scheme: ConstantIndex.CredentialScheme) {
        credentials += SubjectCredentialStore.StoreEntry.Iso(issuerSigned, scheme)
    }

    override suspend fun storeAttachment(name: String, data: ByteArray, vcId: String) {
        attachments += SubjectCredentialStore.AttachmentEntry(name, data, vcId)
    }

    override suspend fun getCredentials(
        requiredAttributeTypes: Collection<String>?,
    ) = KmmResult.success(
        credentials.filter { it.discloseItem(requiredAttributeTypes) }
    )

    private fun SubjectCredentialStore.StoreEntry.discloseItem(
        requiredAttributeTypes: Collection<String>?
    ) = if (requiredAttributeTypes?.isNotEmpty() == true) {
        when (this) {
            is SubjectCredentialStore.StoreEntry.Iso -> this.scheme.vcType in requiredAttributeTypes
            is SubjectCredentialStore.StoreEntry.Vc -> vc.vc.type.any { it in requiredAttributeTypes }
            is SubjectCredentialStore.StoreEntry.SdJwt -> sdJwt.type.any { it in requiredAttributeTypes }
        }
    } else true

    override suspend fun getAttachment(name: String) =
        attachments.firstOrNull { it.name == name }?.data?.let { KmmResult.success(it) }
            ?: KmmResult.failure(NullPointerException("Attachment not found"))

    override suspend fun getAttachment(name: String, vcId: String) =
        attachments.firstOrNull { it.name == name && it.vcId == vcId }?.data?.let { KmmResult.success(it) }
            ?: KmmResult.failure(NullPointerException("Attachment not found"))

}