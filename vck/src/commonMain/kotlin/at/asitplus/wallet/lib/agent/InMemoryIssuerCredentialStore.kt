package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.ReferencedTokenStore
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.Identifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013.IdentifierInfo
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

    /** Tracks revoked identifiers for timePeriod to build [IdentifierList]; Sets to remove duplicates */
    private val identifierRevocationList = mutableMapOf<Int, MutableSet<String>>()

    @Deprecated("Renamed", replaceWith = ReplaceWith("createStoredCredentialReference"))
    override suspend fun createStatusListIndex(
        credential: CredentialToBeIssued,
        timePeriod: Int
    ): KmmResult<IssuerCredentialStore.StoredCredentialReference> =
        createStoredCredentialReference(credential, timePeriod)


    override suspend fun createStoredCredentialReference(
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

    override fun getRawIdentifierList(timePeriod: Int): Map<Identifier, IdentifierInfo> =
        identifierRevocationList.getOrElse(timePeriod) { emptySet() }.associate {
            Identifier(it.encodeToByteArray()) to IdentifierInfo()
        }

    /**
     * Set the [status] of the referenced token with this [index] for the [timePeriod], if it exists.
     *
     * If [status] is [TokenStatus.Invalid] the associated identifier will be added to [identifierRevocationList]
     * Note that ISO 18-013 does not support any action besides full revocation. If a credential has been suspended it remains suspended.
     *
     * Care must be taken to handle drift between the two systems and it is recommended to use only one at a time.
     */
    override fun setStatus(
        timePeriod: Int,
        index: ULong,
        status: TokenStatus,
    ): Boolean {
        val entry = credentialMap.getOrPut(timePeriod) {
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
     * ISO 18-013 does not support any action besides full revocation. If a credential has been suspended it remains suspended
     */
    override fun revokeIdentifier(
        timePeriod: Int,
        identifier: ByteArray
    ): Boolean {
        val entry = credentialMap.getOrPut(timePeriod) {
            mutableListOf()
        }.find {
            it.vcId == identifier.decodeToString()
        } ?: return false

        identifierRevocationList.getOrPut(timePeriod) { mutableSetOf() }.add(entry.vcId)
        entry.status = TokenStatus.Invalid
        return true
    }
}

private val Issuer.IssuedCredential.validUntil: Instant
    get() = when (this) {
        is Issuer.IssuedCredential.Iso -> this.issuerSigned.issuerAuth.payload?.validityInfo?.validUntil
            ?: Instant.DISTANT_PAST

        is Issuer.IssuedCredential.VcJwt -> this.vc.expirationDate ?: Instant.DISTANT_PAST
        is Issuer.IssuedCredential.VcSdJwt -> this.sdJwtVc.expiration ?: Instant.DISTANT_PAST
    }
