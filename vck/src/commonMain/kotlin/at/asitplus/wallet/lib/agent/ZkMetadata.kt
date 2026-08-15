package at.asitplus.wallet.lib.agent

import at.asitplus.iso.ZkRequest

/**
 * Defines metadata for zero-knowledge presentations and a method to evaluate compatibility
 * with specific credential entries stored in the credential store.
 */
sealed interface ZkMetadata {
    fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry): Boolean

    data class IsoMdocZk(val zkRequest: ZkRequest) : ZkMetadata {
        override fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry) = credential is SubjectCredentialStore.StoreEntry.Iso
    }
}