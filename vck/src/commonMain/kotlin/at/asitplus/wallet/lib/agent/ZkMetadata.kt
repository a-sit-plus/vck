package at.asitplus.wallet.lib.agent

import at.asitplus.iso.ZkInfo

/**
 * Defines metadata for zero-knowledge presentations and a method to evaluate compatibility
 * with specific credential entries stored in the credential store.
 */
sealed interface ZkMetadata {
    fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry): Boolean

    data class IsoMdocZk(val zkInfo: ZkInfo) : ZkMetadata {
        override fun isCompatibleWith(credential: SubjectCredentialStore.StoreEntry) = credential is SubjectCredentialStore.StoreEntry.Iso
    }
}