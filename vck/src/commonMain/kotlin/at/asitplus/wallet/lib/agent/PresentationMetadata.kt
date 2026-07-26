package at.asitplus.wallet.lib.agent

import at.asitplus.iso.ZkInfo

/**
 * Defines metadata for presentations and a method to evaluate compatibility
 * with specific credential entries stored in the credential store.
 */
sealed interface PresentationMetadata {
    fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry): Boolean

    data class IsoMdocZk(val zkInfo: ZkInfo) : PresentationMetadata {
        override fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry) = credential is SubjectCredentialStore.StoreEntry.Iso
    }
}