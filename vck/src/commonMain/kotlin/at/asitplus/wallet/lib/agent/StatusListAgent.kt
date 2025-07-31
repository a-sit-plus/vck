package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.CoseHeaderKeyId
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.SignCoseFun
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListAggregation
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * An agent that implements [StatusListIssuer], i.e. it manages status of credentials and status lists.
 */
class StatusListAgent(
    /** Should either be [PublishedKeyMaterial] or contain a certificate, so clients can look up the key. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithSelfSignedCert(),
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val statusListBaseUrl: String = "https://wallet.a-sit.at/backend/credentials/status",
    private val statusListAggregationUrl: String? = null,
    private val zlibService: ZlibService = DefaultZlibService(),
    private val revocationListLifetime: Duration = 48.hours,
    private val clock: Clock = Clock.System,
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
    private val signStatusListJwt: SignJwtFun<StatusListTokenPayload> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signStatusListCwt: SignCoseFun<StatusListTokenPayload> =
        SignCose(keyMaterial, CoseHeaderKeyId(), CoseHeaderCertificate()),
) : StatusListIssuer {

    /**
     * Wraps the revocation information from [issuerCredentialStore] into a Status List Token,
     * returns a JWS representation of that.
     */
    override suspend fun issueStatusListJwt(time: Instant?) =
        signStatusListJwt(
            MediaTypes.STATUSLIST_JWT,
            buildStatusListTokenPayload(time.toTimePeriod()),
            StatusListTokenPayload.serializer(),
        ).getOrElse {
            Napier.w("issueStatusListJwt error", it)
            throw IllegalStateException("Status token could not be created.", it)
        }

    /**
     * Wraps the revocation information from [issuerCredentialStore] into a Status List Token,
     * returns a CWS representation of that.
     */
    override suspend fun issueStatusListCwt(time: Instant?) =
        issueStatusListCwt(time.toTimePeriod())
            ?: throw IllegalStateException("Status token could not be created.")

    suspend fun issueStatusListCwt(timePeriod: Int?): CoseSigned<StatusListTokenPayload>? =
        wrapStatusListTokenInCoseSigned(buildStatusListTokenPayload(timePeriod))

    /**
     * Wraps the revocation information from [issuerCredentialStore] into a Token Payload
     */
    private fun buildStatusListTokenPayload(timePeriod: Int?): StatusListTokenPayload =
        StatusListTokenPayload(
            statusList = buildStatusList(timePeriod),
            issuedAt = clock.now(),
            timeToLive = PositiveDuration(revocationListLifetime),
            subject = UniformResourceIdentifier(
                getRevocationListUrlFor(timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock))
            ),
        ).also {
            Napier.d("revocation status list: ${it.statusList}")
        }

    /**
     * Returns a status list, where the entry at "revocationListIndex" (of the credential) is INVALID if it is revoked
     */
    override fun buildStatusList(timePeriod: Int?): StatusList =
        buildStatusListView(timePeriod).toStatusList(zlibService, statusListAggregationUrl)

    private fun buildStatusListView(timePeriod: Int?): StatusListView =
        issuerCredentialStore.getStatusListView(timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock))

    /**
     * Sets the status of one specific credential to [TokenStatus.Invalid].
     * Returns true if this credential has been revoked.
     */
    override fun revokeCredential(timePeriod: Int, statusListIndex: ULong): Boolean =
        issuerCredentialStore.setStatus(timePeriod, statusListIndex, TokenStatus.Invalid)

    override suspend fun provideStatusListToken(
        acceptedContentTypes: List<StatusListTokenMediaType>,
        time: Instant?,
    ): Pair<StatusListTokenMediaType, StatusListToken> {
        val preferedType = acceptedContentTypes.firstOrNull()
            ?: throw IllegalArgumentException("Argument `acceptedContentTypes` must contain at least one item.")

        return preferedType to when (preferedType) {
            StatusListTokenMediaType.Jwt -> StatusListToken.StatusListJwt(
                issueStatusListJwt(time),
                resolvedAt = clock.now(),
            )

            StatusListTokenMediaType.Cwt -> StatusListToken.StatusListCwt(
                issueStatusListCwt(time),
                resolvedAt = clock.now(),
            )
        }
    }

    override suspend fun provideStatusListAggregation() = StatusListAggregation(
        statusLists = compileCurrentRevocationLists().map {
            UniformResourceIdentifier(it)
        }
    )

    private fun compileCurrentRevocationLists(): List<String> {
        val list = mutableListOf<String>()
        for (timePeriod in timePeriodProvider.getRelevantTimePeriods(clock)) {
            if (timePeriodProvider.getCurrentTimePeriod(clock) == timePeriod
                || issuerCredentialStore.getStatusListView(timePeriod).isNotEmpty()
            ) {
                list.add(getRevocationListUrlFor(timePeriod))
            }
        }
        return list
    }

    private suspend fun wrapStatusListTokenInCoseSigned(
        statusListTokenPayload: StatusListTokenPayload,
    ): CoseSigned<StatusListTokenPayload>? =
        signStatusListCwt(
            protectedHeader = CoseHeader(type = MediaTypes.Application.STATUSLIST_CWT),
            unprotectedHeader = null,
            payload = statusListTokenPayload,
            serializer = StatusListTokenPayload.serializer(),
        ).getOrElse {
            Napier.w("Could not wrapStatusListInJws", it)
            return null
        }

    private fun getRevocationListUrlFor(timePeriod: Int) = statusListBaseUrl.let {
        it + (if (!it.endsWith('/')) "/" else "") + timePeriod
    }

    fun Instant?.toTimePeriod() = this?.let {
        timePeriodProvider.getTimePeriodFor(it)
    } ?: timePeriodProvider.getCurrentTimePeriod(clock)
}
