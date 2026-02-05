package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenStore
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import com.benasher44.uuid.uuid4
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Instant

class InMemoryIssuerCredentialStore(
    val tokenStatusBitSize: TokenStatusBitSize = TokenStatusBitSize.ONE,
) : IssuerCredentialStore, ReferencedTokenStore {

    data class Credential(
        val vcId: String,
        val statusListIndex: ULong,
        var status: TokenStatus,
        val expirationDate: Instant,
        val scheme: ConstantIndex.CredentialScheme,
    )

    /** Maps timePeriod to credentials */
    private val credentialMap = mutableMapOf<Int, MutableList<Credential>>()

    /** Index is map of timePeriod to counter */
    private val indexMap = mutableMapOf<Int, ULong>()
    private val indexMutex = Mutex()

    override suspend fun createStatusListIndex(timePeriod: Int): ULong =
        indexMutex.withLock {
            indexMap.getOrPut(timePeriod) { 0u }.also { index ->
                indexMap[timePeriod] = index + 1u
            }
        }

    override suspend fun storeCredential(
        timePeriod: Int,
        reference: ULong,
        credential: Issuer.IssuedCredential
    ): KmmResult<Boolean> = catching {
        require(reference <= indexMap[timePeriod]!!) { "Invalid reference!" }
        val list = credentialMap.getOrPut(timePeriod) { mutableListOf() }
        require(list.find { it.statusListIndex == reference } == null) { "Reference already used!" }
        list += Credential(
            vcId = uuid4().toString(),
            statusListIndex = reference,
            status = TokenStatus.Valid,
            expirationDate = credential.validUntil,
            scheme = credential.scheme
        )
        true
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

val Issuer.IssuedCredential.validUntil: Instant
    get() = when (this) {
        is Issuer.IssuedCredential.Iso -> this.issuerSigned.issuerAuth.payload?.validityInfo?.validUntil
            ?: Instant.DISTANT_PAST

        is Issuer.IssuedCredential.VcJwt -> this.vc.expirationDate ?: Instant.DISTANT_PAST
        is Issuer.IssuedCredential.VcSdJwt -> this.sdJwtVc.expiration ?: Instant.DISTANT_PAST
    }
