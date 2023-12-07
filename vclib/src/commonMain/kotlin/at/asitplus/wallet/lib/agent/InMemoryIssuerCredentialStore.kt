package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.sha256
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant

class InMemoryIssuerCredentialStore : IssuerCredentialStore {

    data class Credential(
        val vcId: String,
        val statusListIndex: Long,
        var revoked: Boolean,
        val expirationDate: Instant,
        val scheme: ConstantIndex.CredentialScheme,
    )

    private val map = mutableMapOf<Int, MutableList<Credential>>()

    override fun storeGetNextIndex(
        credential: IssuerCredentialStore.Credential,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int
    ): Long {
        val list = map.getOrPut(timePeriod) { mutableListOf() }
        val newIndex = (list.maxOfOrNull { it.statusListIndex } ?: 0) + 1
        val vcId = when (credential) {
            is IssuerCredentialStore.Credential.Iso -> credential.issuerSignedItemList.toString().encodeToByteArray()
                .sha256().encodeToString(Base16(strict = true))

            is IssuerCredentialStore.Credential.VcJwt -> credential.vcId
            is IssuerCredentialStore.Credential.VcSd -> credential.vcId
        }
        val scheme = when (credential) {
            is IssuerCredentialStore.Credential.Iso -> credential.scheme
            is IssuerCredentialStore.Credential.VcJwt -> credential.scheme
            is IssuerCredentialStore.Credential.VcSd -> credential.scheme
        }
        list += Credential(
            vcId = vcId,
            statusListIndex = newIndex,
            revoked = false,
            expirationDate = expirationDate,
            scheme = scheme,
        )
        return newIndex
    }

    override fun getRevokedStatusListIndexList(timePeriod: Int): Collection<Long> {
        return map.getOrPut(timePeriod) { mutableListOf() }.filter { it.revoked }.map { it.statusListIndex }
    }

    override fun revoke(vcId: String, timePeriod: Int): Boolean {
        val entry = map.getOrPut(timePeriod) { mutableListOf() }.find { it.vcId == vcId } ?: return false
        entry.revoked = true
        return true
    }

}