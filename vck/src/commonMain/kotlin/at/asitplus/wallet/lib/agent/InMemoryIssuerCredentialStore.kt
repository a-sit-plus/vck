package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import com.benasher44.uuid.uuid4
import kotlinx.coroutines.sync.Mutex
import kotlin.time.Instant

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
