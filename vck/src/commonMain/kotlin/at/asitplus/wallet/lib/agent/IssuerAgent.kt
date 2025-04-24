package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.CoseHeaderKeyId
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.cbor.SignCoseFun
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.*
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderKeyId
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

/**
 * An agent that only implements [Issuer], i.e. it issues credentials for other agents.
 */

class IssuerAgent(
    override val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val validator: Validator = Validator(),
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val statusListBaseUrl: String = "https://wallet.a-sit.at/backend/credentials/status",
    private val statusListAggregationUrl: String? = null,
    private val zlibService: ZlibService = DefaultZlibService(),
    private val revocationListLifetime: Duration = 48.hours,
    @Deprecated("Use signIssuedSdJwt, signIssuedVc, signStatusListJwt instead")
    private val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    @Deprecated("Use signMobileSecurityObject, signStatusListCwt instead")
    private val coseService: CoseService = DefaultCoseService(DefaultCryptoService(keyMaterial)),
    private val clock: Clock = Clock.System,
    override val cryptoAlgorithms: Set<SignatureAlgorithm> = setOf(keyMaterial.signatureAlgorithm),
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
    /**
     * The identifier used in `issuer` properties of issued credentials.
     * Note that for SD-JWT VC this must be a URI. */
    private val identifier: String = keyMaterial.identifier,
    private val signIssuedSdJwt: SignJwtFun<JsonObject> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signIssuedVc: SignJwtFun<VerifiableCredentialJws> = SignJwt(keyMaterial, JwsHeaderKeyId()),
    private val signStatusListJwt: SignJwtFun<StatusListTokenPayload> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signMobileSecurityObject: SignCoseFun<MobileSecurityObject> =
        SignCose(keyMaterial, CoseHeaderNone(), CoseHeaderCertificate()),
    private val signStatusListCwt: SignCoseFun<StatusListTokenPayload> =
        SignCose(keyMaterial, CoseHeaderKeyId(), CoseHeaderCertificate()),
) : Issuer {

    /**
     * Wraps the credential-to-be-issued in [credential] into a single instance of [CredentialToBeIssued],
     * according to the representation, i.e. it essentially signs the credential with the issuer key.
     */
    override suspend fun issueCredential(
        credential: CredentialToBeIssued,
    ): KmmResult<Issuer.IssuedCredential> = catching {
        when (credential) {
            is CredentialToBeIssued.Iso -> issueMdoc(credential, clock.now())
            is CredentialToBeIssued.VcJwt -> issueVc(credential, clock.now())
            is CredentialToBeIssued.VcSd -> issueVcSd(credential, clock.now())
        }
    }

    private suspend fun issueMdoc(
        credential: CredentialToBeIssued.Iso,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.Iso(
                credential.issuerSignedItems,
                credential.scheme,
            ),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod,
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")
        val deviceKeyInfo = DeviceKeyInfo(credential.subjectPublicKey.toCoseKey().getOrElse { ex ->
            Napier.w("Could not transform SubjectPublicKey to COSE Key", ex)
            throw IllegalArgumentException("SubjectPublicKey transformation failed", ex)
        })
        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = statusListIndex.toULong(),
                uri = UniformResourceIdentifier(getRevocationListUrlFor(timePeriod)),
            ),
        )
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                credential.scheme.isoNamespace!! to ValueDigestList(credential.issuerSignedItems.map {
                    ValueDigest.fromIssuerSignedItem(it, credential.scheme.isoNamespace!!)
                })
            ),
            deviceKeyInfo = deviceKeyInfo,
            docType = credential.scheme.isoDocType!!,
            validityInfo = ValidityInfo(
                signed = issuanceDate,
                validFrom = issuanceDate,
                validUntil = expirationDate,
            ),
            status = credentialStatus
        )
        val issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = mapOf(credential.scheme.isoNamespace!! to credential.issuerSignedItems),
            issuerAuth = signMobileSecurityObject(
                null, null, mso, MobileSecurityObject.serializer(),
            ).getOrThrow(),
        )
        return Issuer.IssuedCredential.Iso(issuerSigned, credential.scheme)
    }

    private suspend fun issueVc(
        credential: CredentialToBeIssued.VcJwt,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(
                vcId,
                credential.subject,
                credential.scheme
            ),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = statusListIndex.toULong(),
                uri = UniformResourceIdentifier(getRevocationListUrlFor(timePeriod)),
            )
        )
        val vc = VerifiableCredential(
            id = vcId,
            issuer = identifier,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            credentialStatus = credentialStatus,
            credentialSubject = credential.subject,
            credentialType = credential.scheme.vcType!!,
        )

        val vcInJws = signIssuedVc(
            JwsContentTypeConstants.JWT,
            vc.toJws(),
            VerifiableCredentialJws.serializer(),
        ).getOrElse {
            Napier.w("issueVc error", it)
            throw RuntimeException("Signing failed", it)
        }.serialize()

        return Issuer.IssuedCredential.VcJwt(vcInJws, credential.scheme)
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val subjectId = credential.subjectPublicKey.didEncoded
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcSd(
                vcId,
                credential.claims,
                credential.scheme
            ),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = statusListIndex.toULong(),
                uri = UniformResourceIdentifier(getRevocationListUrlFor(timePeriod)),
            ),
        )

        val (sdJwt, disclosures) = credential.claims.toSdJsonObject()
        val cnf = ConfirmationClaim(jsonWebKey = credential.subjectPublicKey.toJsonWebKey())
        val vcSdJwt = VerifiableCredentialSdJwt(
            subject = subjectId,
            notBefore = issuanceDate,
            issuer = identifier,
            expiration = expirationDate,
            issuedAt = issuanceDate,
            jwtId = vcId,
            verifiableCredentialType = credential.scheme.sdJwtType ?: credential.scheme.schemaUri,
            selectiveDisclosureAlgorithm = SdJwtConstants.SHA_256,
            confirmationClaim = cnf,
            statusElement = vckJsonSerializer.encodeToJsonElement(credentialStatus),
        )
        val vcSdJwtObject = vckJsonSerializer.encodeToJsonElement(vcSdJwt).jsonObject
        val entireObject = buildJsonObject {
            sdJwt.forEach {
                put(it.key, it.value)
            }
            vcSdJwtObject.forEach {
                put(it.key, it.value)
            }
        }
        // inclusion of x5c/jwk may change when all clients can look up the issuer-signed key web-based,
        // i.e. this issuer provides `.well-known/jwt-vc-issuer` file
        val jws = signIssuedSdJwt(
            JwsContentTypeConstants.SD_JWT,
            entireObject,
            JsonObject.serializer(),
        ).getOrElse {
            Napier.w("Could not wrap credential in SD-JWT", it)
            throw RuntimeException("Signing failed", it)
        }
        val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
        Napier.i("issueVcSd: $vcInSdJwt")
        return Issuer.IssuedCredential.VcSdJwt(vcInSdJwt, credential.scheme)
    }

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
        StatusList(
            view = buildStatusListView(timePeriod),
            aggregationUri = statusListAggregationUrl,
            zlibService = zlibService,
        )

    private fun buildStatusListView(timePeriod: Int?): StatusListView =
        issuerCredentialStore.getStatusListView(timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock))

    /**
     * Revokes all verifiable credentials from [credentialsToRevoke] list that parse and validate.
     * It returns true if all revocations was successful.
     */
    override suspend fun revokeCredentials(credentialsToRevoke: List<String>): Boolean =
        credentialsToRevoke.map {
            validator.verifyVcJws(it, null)
        }.filterIsInstance<Verifier.VerifyCredentialResult.SuccessJwt>().all {
            issuerCredentialStore.setStatus(
                vcId = it.jws.vc.id,
                status = TokenStatus.Invalid,
                timePeriod = timePeriodProvider.getTimePeriodFor(it.jws.vc.issuanceDate)
            )
        }

    /**
     * Revokes all verifiable credentials with ids from [credentialIdsToRevoke]
     * It returns true if all revocations was successful.
     */
    override fun revokeCredentialsWithId(credentialIdsToRevoke: Map<String, Instant>): Boolean =
        credentialIdsToRevoke.all {
            issuerCredentialStore.setStatus(
                vcId = it.key,
                status = TokenStatus.Invalid,
                timePeriod = timePeriodProvider.getTimePeriodFor(it.value),
            )
        }

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

    private suspend fun wrapStatusListTokenInCoseSigned(statusListTokenPayload: StatusListTokenPayload): CoseSigned<StatusListTokenPayload>? =
        signStatusListCwt(
            CoseHeader(type = MediaTypes.Application.STATUSLIST_CWT),
            null,
            statusListTokenPayload,
            StatusListTokenPayload.serializer(),
        ).getOrElse {
            Napier.w("Could not wrapStatusListInJws", it)
            return null
        }

    private fun getRevocationListUrlFor(timePeriod: Int) = statusListBaseUrl.let {
        it + (if (!it.endsWith('/')) "/" else "") + timePeriod
    }

    private fun VerifiableCredential.toJws() = VerifiableCredentialJws(
        vc = this,
        subject = credentialSubject.id,
        notBefore = issuanceDate,
        issuer = issuer,
        expiration = expirationDate,
        jwtId = id
    )

    fun Instant?.toTimePeriod() = this?.let {
        timePeriodProvider.getTimePeriodFor(it)
    } ?: timePeriodProvider.getCurrentTimePeriod(clock)
}
