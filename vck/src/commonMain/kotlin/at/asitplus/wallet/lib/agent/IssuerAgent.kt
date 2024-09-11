package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.BitSet
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.wallet.lib.DataSourceProblem
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialStatus
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VcDataModelConstants.REVOCATION_LIST_MIN_SIZE
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.DeviceKeyInfo
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedList
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.iso.ValidityInfo
import at.asitplus.wallet.lib.iso.ValueDigest
import at.asitplus.wallet.lib.iso.ValueDigestList
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours

/**
 * An agent that only implements [Issuer], i.e. it issues credentials for other agents.
 */
class IssuerAgent(
    private val validator: Validator,
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val revocationListBaseUrl: String = "https://wallet.a-sit.at/backend/credentials/status",
    private val dataProvider: IssuerCredentialDataProvider = EmptyCredentialDataProvider,
    private val zlibService: ZlibService = DefaultZlibService(),
    private val revocationListLifetime: Duration = 48.hours,
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val clock: Clock = Clock.System,
    override val keyPair: KeyWithCert,
    override val cryptoAlgorithms: Set<X509SignatureAlgorithm>,
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
) : Issuer {

    constructor(
        keyWithCert: KeyWithCert = EphemeralKeyWithSelfSignedCert(),
        dataProvider: IssuerCredentialDataProvider = EmptyCredentialDataProvider,
    ) : this(
        validator = Validator(),
        jwsService = DefaultJwsService(DefaultCryptoService(keyWithCert)),
        coseService = DefaultCoseService(DefaultCryptoService(keyWithCert)),
        dataProvider = dataProvider,
        keyPair = keyWithCert,
        cryptoAlgorithms = setOf(keyWithCert.x509SignatureAlgorithm),
    )

    constructor(
        keyWithCert: KeyWithCert = EphemeralKeyWithSelfSignedCert(),
        issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
        dataProvider: IssuerCredentialDataProvider = EmptyCredentialDataProvider,
    ) : this(
        validator = Validator(),
        issuerCredentialStore = issuerCredentialStore,
        jwsService = DefaultJwsService(DefaultCryptoService(keyWithCert)),
        coseService = DefaultCoseService(DefaultCryptoService(keyWithCert)),
        dataProvider = dataProvider,
        keyPair = keyWithCert,
        cryptoAlgorithms = setOf(keyWithCert.x509SignatureAlgorithm),
    )

    /**
     * Issues credentials for some [credentialScheme] to the subject specified with its public
     * key in [subjectPublicKey] in the format specified by [representation].
     * Callers may optionally define some attribute names from [ConstantIndex.CredentialScheme.claimNames] in
     * [claimNames] to request only some claims (if supported by the representation).
     *
     * @param dataProviderOverride Set this parameter to override the default [dataProvider] for this issuing process
     */
    override suspend fun issueCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
        dataProviderOverride: IssuerCredentialDataProvider?
    ): KmmResult<Issuer.IssuedCredential> = catching {
        val provider = dataProviderOverride ?: dataProvider
        val toBeIssued =
            provider.getCredential(subjectPublicKey, credentialScheme, representation, claimNames).getOrThrow()
        issueCredential(toBeIssued, subjectPublicKey, credentialScheme).getOrThrow()
    }

    /**
     * Wraps the credential-to-be-issued in [credential] into a single instance of [CredentialToBeIssued],
     * according to the representation, i.e. it essentially signs the credential with the issuer key.
     */
    suspend fun issueCredential(
        credential: CredentialToBeIssued,
        subjectPublicKey: CryptoPublicKey,
        scheme: ConstantIndex.CredentialScheme,
    ): KmmResult<Issuer.IssuedCredential> = catching {
        when (credential) {
            is CredentialToBeIssued.Iso -> issueMdoc(credential, scheme, subjectPublicKey, clock.now())
            is CredentialToBeIssued.VcJwt -> issueVc(credential, scheme, subjectPublicKey, clock.now())
            is CredentialToBeIssued.VcSd -> issueVcSd(credential, scheme, subjectPublicKey, clock.now())
        }
    }

    private suspend fun issueMdoc(
        credential: CredentialToBeIssued.Iso,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant
    ): Issuer.IssuedCredential {
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.Iso(credential.issuerSignedItems, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod,
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")
        val deviceKeyInfo = DeviceKeyInfo(subjectPublicKey.toCoseKey().getOrElse { ex ->
            Napier.w("Could not transform SubjectPublicKey to COSE Key", ex)
            throw DataSourceProblem("SubjectPublicKey transformation failed", ex.message, ex)
        })
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                scheme.isoNamespace!! to ValueDigestList(credential.issuerSignedItems.map {
                    ValueDigest.fromIssuerSigned(it)
                })
            ),
            deviceKeyInfo = deviceKeyInfo,
            docType = scheme.isoDocType!!,
            validityInfo = ValidityInfo(
                signed = issuanceDate,
                validFrom = issuanceDate,
                validUntil = expirationDate,
            )
        )
        val issuerSigned = IssuerSigned(
            namespaces = mapOf(
                scheme.isoNamespace!! to IssuerSignedList.withItems(credential.issuerSignedItems)
            ),
            issuerAuth = coseService.createSignedCose(
                payload = mso.serializeForIssuerAuth(),
                addKeyId = false,
                addCertificate = true,
            ).getOrThrow()
        )
        return Issuer.IssuedCredential.Iso(issuerSigned, scheme)
    }

    private suspend fun issueVc(
        credential: CredentialToBeIssued.VcJwt,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(vcId, credential.subject, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)
        val vc = VerifiableCredential(
            id = vcId,
            issuer = keyPair.identifier,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            credentialStatus = credentialStatus,
            credentialSubject = credential.subject,
            credentialType = scheme.vcType!!,
        )

        val vcInJws = wrapVcInJws(vc)
            ?: throw RuntimeException("Signing failed")
        return Issuer.IssuedCredential.VcJwt(vcInJws, scheme)
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val subjectId = subjectPublicKey.didEncoded
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcSd(vcId, credential.claims, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)
        val disclosures = credential.claims
            .map { SelectiveDisclosureItem(Random.nextBytes(32), it.name, it.value) }
            .map { it.toDisclosure() }
        val disclosureDigests = disclosures
            .map { it.hashDisclosure() }
        val jwsPayload = VerifiableCredentialSdJwt(
            subject = subjectId,
            notBefore = issuanceDate,
            issuer = keyPair.identifier,
            expiration = expirationDate,
            issuedAt = issuanceDate,
            jwtId = vcId,
            disclosureDigests = disclosureDigests,
            verifiableCredentialType = scheme.sdJwtType ?: scheme.schemaUri,
            selectiveDisclosureAlgorithm = "sha-256",
            confirmationKey = subjectPublicKey.toJsonWebKey(),
            credentialStatus = credentialStatus,
        ).serialize().encodeToByteArray()
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.SD_JWT, jwsPayload).getOrElse {
            Napier.w("Could not wrap credential in SD-JWT", it)
            throw RuntimeException("Signing failed", it)
        }
        val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~")
        return Issuer.IssuedCredential.VcSdJwt(vcInSdJwt, scheme)
    }

    /**
     * Wraps the revocation information from [issuerCredentialStore] into a VC,
     * returns a JWS representation of that.
     */
    override suspend fun issueRevocationListCredential(timePeriod: Int?): String? {
        val revocationListUrl =
            getRevocationListUrlFor(timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock))
        val revocationList = buildRevocationList(timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock))
            ?: return null
        val subject = RevocationListSubject("$revocationListUrl#list", revocationList)
        val credential = VerifiableCredential(
            id = revocationListUrl,
            issuer = keyPair.identifier,
            issuanceDate = clock.now(),
            lifetime = revocationListLifetime,
            credentialSubject = subject
        )
        return wrapVcInJws(credential)
    }

    /**
     * Returns a Base64-encoded, zlib-compressed bitstring of revoked credentials, where
     * the entry at "revocationListIndex" (of the credential) is true iff it is revoked
     */
    override fun buildRevocationList(timePeriod: Int?): String? {
        val bitset = BitSet(REVOCATION_LIST_MIN_SIZE)
        issuerCredentialStore.getRevokedStatusListIndexList(
            timePeriod ?: timePeriodProvider.getCurrentTimePeriod(clock)
        ).forEach { bitset[it] = true }
        val input = bitset.toByteArray()
        return zlibService.compress(input)?.encodeToString(Base64Strict)
    }

    /**
     * Revokes all verifiable credentials from [credentialsToRevoke] list that parse and validate.
     * It returns true if all revocations was successful.
     */
    override fun revokeCredentials(credentialsToRevoke: List<String>): Boolean =
        credentialsToRevoke.map { validator.verifyVcJws(it, null) }
            .filterIsInstance<Verifier.VerifyCredentialResult.SuccessJwt>()
            .all {
                issuerCredentialStore.revoke(
                    vcId = it.jws.vc.id,
                    timePeriod = timePeriodProvider.getTimePeriodFor(it.jws.vc.issuanceDate)
                )
            }

    /**
     * Revokes all verifiable credentials with ids from [credentialIdsToRevoke]
     * It returns true if all revocations was successful.
     */
    override fun revokeCredentialsWithId(credentialIdsToRevoke: Map<String, Instant>): Boolean =
        credentialIdsToRevoke.all {
            issuerCredentialStore.revoke(
                vcId = it.key,
                timePeriod = timePeriodProvider.getTimePeriodFor(it.value)
            )
        }

    override fun compileCurrentRevocationLists(): List<String> {
        val list = mutableListOf<String>()
        for (timePeriod in timePeriodProvider.getRelevantTimePeriods(clock)) {
            if (timePeriodProvider.getCurrentTimePeriod(clock) == timePeriod
                || issuerCredentialStore.getRevokedStatusListIndexList(timePeriod).isNotEmpty()
            ) {
                list.add(getRevocationListUrlFor(timePeriod))
            }
        }
        return list
    }

    private suspend fun wrapVcInJws(vc: VerifiableCredential): String? {
        val jwsPayload = vc.toJws().serialize().encodeToByteArray()
        return jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrElse {
            Napier.w("Could not wrapVcInJws", it)
            return null
        }.serialize()
    }

    private fun getRevocationListUrlFor(timePeriod: Int) =
        revocationListBaseUrl.let { it + (if (!it.endsWith('/')) "/" else "") + timePeriod }

    private fun VerifiableCredential.toJws() = VerifiableCredentialJws(
        vc = this,
        subject = credentialSubject.id,
        notBefore = issuanceDate,
        issuer = issuer,
        expiration = expirationDate,
        jwtId = id
    )
}
