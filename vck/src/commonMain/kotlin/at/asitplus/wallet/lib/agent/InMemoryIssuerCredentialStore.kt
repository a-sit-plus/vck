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
import kotlin.time.Instant

class InMemoryIssuerCredentialStore(
    val tokenStatusBitSize: TokenStatusBitSize = TokenStatusBitSize.ONE,
) : IssuerCredentialStore, ReferencedTokenStore {
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
    private val indexMap = mutableMapOf<Int, MutableList<ULong>>()

    override suspend fun createStatusListIndex(
        timePeriod: Int,
    ): ULong = indexMap.getOrPut(timePeriod) { mutableListOf() }.maxOfOrNull { it + 1U } ?: 0U

    override suspend fun storeCredential(
        timePeriod: Int,
        reference: ULong,
        validUntil: Instant,
        scheme: ConstantIndex.CredentialScheme
    ): KmmResult<Boolean> = catching {
        val list = credentialMap.getOrElse(timePeriod) { throw Exception("Credential $timePeriod not found") }
            list += Credential(
                vcId = uuid4().toString(),
                statusListIndex = reference,
                status = TokenStatus.Valid,
                expirationDate = validUntil,
                scheme = scheme
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
