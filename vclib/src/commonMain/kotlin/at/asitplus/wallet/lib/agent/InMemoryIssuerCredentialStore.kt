package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.CredentialSubject
import kotlin.time.Instant


class InMemoryIssuerCredentialStore : IssuerCredentialStore {

    data class Credential(
        val vcId: String,
        val statusListIndex: Long,
        var revoked: Boolean,
        val expirationDate: Instant
    )

    private val map = mutableMapOf<Int, MutableList<Credential>>()

    override fun storeGetNextIndex(
        vcId: String,
        credentialSubject: CredentialSubject,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int
    ): Long {
        val list = map.getOrPut(timePeriod) { mutableListOf() }
        val newIndex = (list.maxOfOrNull { it.statusListIndex } ?: 0) + 1
        list += Credential(
            vcId = vcId,
            statusListIndex = newIndex,
            revoked = false,
            expirationDate = expirationDate
        )
        return newIndex
    }

    override fun getRevokedStatusListIndexList(timePeriod: Int): Collection<Long> {
        return  map.getOrPut(timePeriod) { mutableListOf() }.filter { it.revoked }.map { it.statusListIndex }
    }

    override fun revoke(vcId: String, timePeriod: Int): Boolean {
        val entry =  map.getOrPut(timePeriod) { mutableListOf() }.find { it.vcId == vcId } ?: return false
        entry.revoked = true
        return true
    }

}