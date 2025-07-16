package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.iso.sha256
import com.benasher44.uuid.uuid4
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
        val statusListIndex: ULong,
        var status: TokenStatus,
        val expirationDate: Instant,
        val scheme: ConstantIndex.CredentialScheme,
    )

    /** Maps timePeriod to credentials */
    private val credentialMap = mutableMapOf<Int, MutableList<Credential>>()

    @Suppress("DEPRECATION")
    @Deprecated("Use `createStatusListIndex` and `updateStoredCredential` instead")
    override suspend fun storeGetNextIndex(
        credential: IssuerCredentialStore.Credential,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
        expirationDate: Instant,
        timePeriod: Int
    ): Long = indexMutex.withLock {
        val list = credentialMap.getOrPut(timePeriod) { mutableListOf() }
        val newIndex: ULong = (list.maxOfOrNull { it.statusListIndex } ?: 0U) + 1U
        val vcId = when (credential) {
            is IssuerCredentialStore.Credential.Iso -> credential.issuerSignedItemList
                .sortedBy { it.digestId }
                .toString()
                .encodeToByteArray().sha256()
                .encodeToString(Base16(strict = true))

            is IssuerCredentialStore.Credential.VcJwt -> credential.vcId
            is IssuerCredentialStore.Credential.VcSd -> credential.vcId
        }
        list += Credential(
            vcId = vcId,
            statusListIndex = newIndex,
            status = TokenStatus.Valid,
            expirationDate = expirationDate,
            scheme = credential.scheme,
        )
        newIndex.toLong()
    }

    override suspend fun createStatusListIndex(
        credential: CredentialToBeIssued,
        timePeriod: Int,
    ): KmmResult<IssuerCredentialStore.StoredCredentialReference> = catching {
        val list = credentialMap.getOrPut(timePeriod) { mutableListOf() }
        val newIndex: ULong = (list.maxOfOrNull { it.statusListIndex } ?: 0U) + 1U
        val vcId = uuid4().toString()
        list += Credential(
            vcId = vcId,
            statusListIndex = newIndex,
            status = TokenStatus.Valid,
            expirationDate = credential.expiration,
            scheme = credential.scheme,
        )
        IssuerCredentialStore.StoredCredentialReference(vcId, timePeriod, newIndex)
    }

    override suspend fun updateStoredCredential(
        reference: IssuerCredentialStore.StoredCredentialReference,
        credential: Issuer.IssuedCredential,
    ): KmmResult<IssuerCredentialStore.StoredCredentialReference> = catching {
        val list = credentialMap.getOrPut(reference.timePeriod) { mutableListOf() }
        if (list.find { it.vcId == reference.id } == null) {
            list += Credential(
                vcId = reference.id,
                statusListIndex = reference.statusListIndex,
                status = TokenStatus.Valid,
                expirationDate = credential.validUntil,
                scheme = credential.scheme
            )
        }
        reference
    }

    override fun getStatusListView(timePeriod: Int): StatusListView {
        val timePeriodStatusCollection = credentialMap[timePeriod]
            ?: return StatusListView(ByteArray(0), tokenStatusBitSize)

        val timePeriodStatusMap = timePeriodStatusCollection.associate {
            it.statusListIndex to it.status
        }
        val highestIndex = timePeriodStatusMap.keys.maxOrNull()
            ?: return StatusListView(ByteArray(0), tokenStatusBitSize)

        val tokenStatusList = (0U..highestIndex.toUInt()).map {
            timePeriodStatusMap[it.toULong()] ?: TokenStatus.Valid
        }

        return StatusListView.fromTokenStatuses(
            tokenStatusList,
            statusBitSize = tokenStatusBitSize,
        )
    }

    @Deprecated("Use setStatus(timePeriod, index, status) instead")
    override fun setStatus(vcId: String, status: TokenStatus, timePeriod: Int): Boolean {
        if(status.value > tokenStatusBitSize.maxValue) {
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

    override fun setStatus(
        timePeriod: Int,
        index: ULong,
        status: TokenStatus,
    ): Boolean {
        if (status.value > tokenStatusBitSize.maxValue) {
            throw IllegalStateException("Credential store only accepts token statuses of bitlength `${tokenStatusBitSize.value}`.")
        }
        val entry = credentialMap.getOrPut(timePeriod) {
            mutableListOf()
        }.find {
            it.statusListIndex == index
        } ?: return false

        entry.status = status
        return true
    }
}

private val Issuer.IssuedCredential.validUntil: Instant
    get() = when (this) {
        is Issuer.IssuedCredential.Iso -> this.issuerSigned.issuerAuth.payload?.validityInfo?.validUntil ?: Instant.DISTANT_PAST
        is Issuer.IssuedCredential.VcJwt -> this.vc.expirationDate?: Instant.DISTANT_PAST
        is Issuer.IssuedCredential.VcSdJwt -> this.sdJwtVc.expiration ?: Instant.DISTANT_PAST
    }
