package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenStore
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import com.benasher44.uuid.uuid4
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class InMemoryIssuerCredentialStore(
    val tokenStatusBitSize: TokenStatusBitSize = TokenStatusBitSize.ONE,
) : IssuerCredentialStore, ReferencedTokenStore {
    private val indexMutex = Mutex()

    data class Credential(
        val vcId: String,
        val statusListIndex: ULong,
        var status: TokenStatus,
    ) {
        /** For JVM callers which can't access ULong directly */
        internal constructor(
            vcId: String,
            status: TokenStatus,
            statusListIndex: Long,
        ) : this(
            vcId = vcId,
            statusListIndex = statusListIndex.toULong().also {
                require(statusListIndex >= 0) { "statusListIndex must be non-negative" }
            },
            status = status
        )
    }

    /** Maps timePeriod to credentials for referenced tokens which may be revoked later on */
    private val referencedTokens = mutableMapOf<Int, MutableList<Credential>>()

    /** Tracks issued credentials */
    private val issuedCredentials = mutableListOf<Issuer.IssuedCredential>()

    /** Tracks revoked identifiers for timePeriod to build [IdentifierList]; Sets to remove duplicates */
    private val identifierRevocationList = mutableMapOf<Int, MutableSet<String>>()

    override suspend fun storeReferencedToken(
        credential: CredentialToBeIssued,
        timePeriod: Int,
    ): KmmResult<ReferencedTokenStore.StoredCredentialReference> = catching {
        indexMutex.withLock {
            val list = referencedTokens.getOrPut(timePeriod) { mutableListOf() }
            val newIndex: ULong = (list.maxOfOrNull { it.statusListIndex } ?: 0U) + 1U
            val vcId = uuid4().toString()
            list += Credential(
                vcId = vcId,
                statusListIndex = newIndex,
                status = TokenStatus.Valid,
            )
            ReferencedTokenStore.StoredCredentialReference(
                id = vcId,
                timePeriod = timePeriod,
                statusListIndex = newIndex
            )
        }
    }

    override suspend fun onCredentialIssued(credential: Issuer.IssuedCredential) {
        issuedCredentials += credential
    }

    override fun getStatusListView(timePeriod: Int): StatusListView {
        val timePeriodStatusCollection = referencedTokens[timePeriod]
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

    override fun getRawIdentifierList(timePeriod: Int): Map<Identifier, IdentifierInfo> =
        identifierRevocationList.getOrElse(timePeriod) { emptySet() }.associate {
            Identifier(it.encodeToByteArray()) to IdentifierInfo()
        }

    /**
     * Set the [status] of the referenced token with this [index] for the [timePeriod], if it exists.
     *
     * If [status] is [TokenStatus.Invalid] the associated identifier will be added to [identifierRevocationList]
     * Note that ISO 18-013 does not support any action besides full revocation.
     * If a credential has been suspended, it remains suspended.
     *
     * Care must be taken to handle drift between the two systems and it is recommended to use only one at a time.
     */
    override fun setStatus(
        timePeriod: Int,
        index: ULong,
        status: TokenStatus,
    ): Boolean {
        val entry = referencedTokens.getOrPut(timePeriod) {
            mutableListOf()
        }.find {
            it.statusListIndex == index
        } ?: return false

        entry.status = status
        if (status == TokenStatus.Invalid) {
            identifierRevocationList.getOrPut(timePeriod) { mutableSetOf() }.add(entry.vcId)
        }
        return true
    }

    /**
     * Set the status of the referenced token with this [identifier] for the [timePeriod] to revoked, if it exists.
     * Additionally the `TokenStatus` at the associated `StatusListIndex` is also automatically set to invalid
     *
     * ISO 18-013 does not support any action besides full revocation.
     * If a credential has been suspended, it remains suspended.
     */
    override fun revokeIdentifier(
        timePeriod: Int,
        identifier: ByteArray
    ): Boolean {
        val entry = referencedTokens.getOrPut(timePeriod) {
            mutableListOf()
        }.find {
            it.vcId == identifier.decodeToString()
        } ?: return false

        identifierRevocationList.getOrPut(timePeriod) { mutableSetOf() }.add(entry.vcId)
        entry.status = TokenStatus.Invalid
        return true
    }
}

