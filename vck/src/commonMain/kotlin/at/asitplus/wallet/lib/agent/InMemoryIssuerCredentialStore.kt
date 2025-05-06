package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.iso.sha256
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Instant

class InMemoryIssuerCredentialStore(
    val tokenStatusBitSize: TokenStatusBitSize = TokenStatusBitSize.ONE,
) : IssuerCredentialStore {
    private val indexMutex = Mutex()

    data class Credential(
        val vcId: String,
        val statusListIndex: Long,
        var status: TokenStatus,
        val expirationDate: Instant,
        val scheme: ConstantIndex.CredentialScheme,
    )

    private val credentialMap = mutableMapOf<Int, MutableList<Credential>>()

    override suspend fun storeGetNextIndex(
        credential: IssuerCredentialStore.Credential,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int,
    ): Long = indexMutex.withLock {
        val list = credentialMap.getOrPut(timePeriod) {
            mutableListOf()
        }

        val newIndex = (list.maxOfOrNull { it.statusListIndex } ?: 0) + 1
        val vcId = when (credential) {
            is IssuerCredentialStore.Credential.Iso -> credential.issuerSignedItemList.sortedBy {
                it.digestId
            }.toString().encodeToByteArray().sha256().encodeToString(Base16(strict = true))

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
            status = TokenStatus.Valid,
            expirationDate = expirationDate,
            scheme = scheme,
        )
        newIndex
    }

    override fun getStatusListView(timePeriod: Int): StatusListView {
        val timePeriodStatusCollection = credentialMap[timePeriod] ?: return StatusListView(
            ByteArray(0),
            statusBitSize = tokenStatusBitSize,
        )

        val timePeriodStatusMap = timePeriodStatusCollection.associate {
            it.statusListIndex to it.status
        }
        val highestIndex = timePeriodStatusMap.keys.maxOrNull() ?: return StatusListView(
            ByteArray(0),
            statusBitSize = tokenStatusBitSize,
        )

        val tokenStatusList = (0..highestIndex).map {
            timePeriodStatusMap[it] ?: TokenStatus.Valid
        }

        return StatusListView.fromTokenStatuses(
            tokenStatusList,
            statusBitSize = tokenStatusBitSize,
        )
    }

    override fun setStatus(vcId: String, status: TokenStatus, timePeriod: Int): Boolean {
        if (status.value > tokenStatusBitSize.maxValue) {
            throw IllegalStateException("Credential store only accepts token statuses of bitlength `${tokenStatusBitSize.value}`.")
        }
        val entry = credentialMap.getOrPut(timePeriod) {
            mutableListOf()
        }.find {
            it.vcId == vcId
        } ?: return false

        entry.status = status
        return true
    }
}