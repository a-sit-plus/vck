package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.cose.CoseAlgorithm
import at.asitplus.crypto.datatypes.cose.CoseHeader
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.DataSourceProblem
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.KmmBitSet
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.REVOCATION_LIST_MIN_SIZE
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import okio.ByteString.Companion.toByteString
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
    override val identifier: String,
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
) : Issuer {

    companion object {
        fun newDefaultInstance(
            cryptoService: CryptoService = DefaultCryptoService(),
            verifierCryptoService: VerifierCryptoService = DefaultVerifierCryptoService(),
            issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
            clock: Clock = Clock.System,
            timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
            dataProvider: IssuerCredentialDataProvider = EmptyCredentialDataProvider,
        ): IssuerAgent = IssuerAgent(
            validator = Validator.newDefaultInstance(
                cryptoService = verifierCryptoService,
                parser = Parser(clock.now().toEpochMilliseconds())
            ),
            issuerCredentialStore = issuerCredentialStore,
            jwsService = DefaultJwsService(cryptoService),
            coseService = DefaultCoseService(cryptoService),
            dataProvider = dataProvider,
            identifier = cryptoService.publicKey.didEncoded,
            timePeriodProvider = timePeriodProvider,
            clock = clock,
        )
    }

    /**
     * Issues credentials for some [attributeTypes] (i.e. some of
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme.vcType]) to the subject specified with its public
     * key in [subjectPublicKey] in the format specified by [representation].
     * Callers may optionally define some attribute names from [ConstantIndex.CredentialScheme.claimNames] in
     * [claimNames] to request only some claims (if supported by the representation).
     */
    override suspend fun issueCredential(
        subjectPublicKey: CryptoPublicKey,
        attributeTypes: Collection<String>,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
    ): Issuer.IssuedCredentialResult {
        val failed = mutableListOf<Issuer.FailedAttribute>()
        val successful = mutableListOf<Issuer.IssuedCredential>()
        for (attributeType in attributeTypes) {
            val scheme = AttributeIndex.resolveAttributeType(attributeType)
            if (scheme == null) {
                failed += Issuer.FailedAttribute(attributeType, IllegalArgumentException("type not resolved to scheme"))
                continue
            }
            dataProvider.getCredential(subjectPublicKey, scheme, representation, claimNames).fold(
                onSuccess = { toBeIssued ->
                    toBeIssued.forEach { credentialToBeIssued ->
                        issueCredential(credentialToBeIssued, subjectPublicKey, scheme).also { result ->
                            failed += result.failed
                            successful += result.successful
                        }
                    }
                },
                onFailure = { failed += Issuer.FailedAttribute(attributeType, it) }
            )
        }
        return Issuer.IssuedCredentialResult(successful = successful, failed = failed)
    }

    /**
     * Wraps the credential-to-be-issued in [credential] into a single instance of [CredentialToBeIssued],
     * according to the representation, i.e. it essentially signs the credential with the issuer key.
     */
    suspend fun issueCredential(
        credential: CredentialToBeIssued,
        subjectPublicKey: CryptoPublicKey,
        scheme: ConstantIndex.CredentialScheme,
    ): Issuer.IssuedCredentialResult = when (credential) {
        is CredentialToBeIssued.Iso -> issueMdoc(credential, scheme, subjectPublicKey, clock.now())
        is CredentialToBeIssued.VcJwt -> issueVc(credential, scheme, subjectPublicKey, clock.now())
        is CredentialToBeIssued.VcSd -> issueVcSd(credential, scheme, subjectPublicKey, clock.now())
    }

    private suspend fun issueMdoc(
        credential: CredentialToBeIssued.Iso,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant
    ): Issuer.IssuedCredentialResult {
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.Iso(credential.issuerSignedItems, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod,
        ) ?: return Issuer.IssuedCredentialResult(
            failed = listOf(Issuer.FailedAttribute(scheme.vcType, DataSourceProblem("vcId internal mismatch")))
        ).also { Napier.w("Got no statusListIndex from issuerCredentialStore, can't issue credential") }
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                scheme.isoNamespace to ValueDigestList(credential.issuerSignedItems.map {
                    ValueDigest.fromIssuerSigned(it)
                })
            ),
            deviceKeyInfo = DeviceKeyInfo(subjectPublicKey.toCoseKey().getOrElse {
                return Issuer.IssuedCredentialResult(
                    failed = listOf(Issuer.FailedAttribute(scheme.vcType, DataSourceProblem("SubjectPublicKey transformation failed")))
                ).also { Napier.w("Could not transform SubjectPublicKey to COSE Key") }
            }),
            docType = scheme.isoDocType,
            validityInfo = ValidityInfo(
                signed = issuanceDate,
                validFrom = issuanceDate,
                validUntil = expirationDate,
            )
        )
        val issuerSigned = IssuerSigned(
            namespaces = mapOf(
                scheme.isoNamespace to IssuerSignedList.withItems(credential.issuerSignedItems)
            ),
            issuerAuth = coseService.createSignedCose(
                protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
                unprotectedHeader = null,
                payload = mso.serializeForIssuerAuth(),
                addKeyId = false,
                addCertificate = true,
            ).getOrThrow()
        )
        return Issuer.IssuedCredentialResult(successful = listOf(Issuer.IssuedCredential.Iso(issuerSigned, scheme)))
    }

    private suspend fun issueVc(
        credential: CredentialToBeIssued.VcJwt,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant,
    ): Issuer.IssuedCredentialResult {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(vcId, credential.subject, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: return Issuer.IssuedCredentialResult(
            failed = listOf(Issuer.FailedAttribute(scheme.vcType, DataSourceProblem("vcId internal mismatch")))
        ).also { Napier.w("Got no statusListIndex from issuerCredentialStore, can't issue credential") }

        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)
        val vc = VerifiableCredential(
            id = vcId,
            issuer = identifier,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            credentialStatus = credentialStatus,
            credentialSubject = credential.subject,
            credentialType = scheme.vcType,
        )

        val vcInJws = wrapVcInJws(vc)
            ?: return Issuer.IssuedCredentialResult(
                failed = listOf(Issuer.FailedAttribute(scheme.vcType, RuntimeException("signing failed")))
            ).also { Napier.w("Could not wrap credential in JWS") }
        return Issuer.IssuedCredentialResult(
            successful = listOf(
                Issuer.IssuedCredential.VcJwt(
                    vcJws = vcInJws,
                    scheme = scheme,
                    attachments = credential.attachments
                )
            )
        )
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        scheme: ConstantIndex.CredentialScheme,
        subjectPublicKey: CryptoPublicKey,
        issuanceDate: Instant
    ): Issuer.IssuedCredentialResult {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val subjectId = subjectPublicKey.toJsonWebKey().keyId ?: return Issuer.IssuedCredentialResult(
            failed = listOf(
                Issuer.FailedAttribute(
                    scheme.vcType,
                    DataSourceProblem("subjectPublicKey transformation error")
                )
            )
        ).also { Napier.w("subjectPublicKey could not be transformed to a JWK") }
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcSd(vcId, credential.claims, scheme),
            subjectPublicKey = subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: return Issuer.IssuedCredentialResult(
            failed = listOf(Issuer.FailedAttribute(scheme.vcType, DataSourceProblem("vcId internal mismatch")))
        ).also { Napier.w("Got no statusListIndex from issuerCredentialStore, can't issue credential") }
        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)

        val disclosures = credential.claims
            .map { SelectiveDisclosureItem(Random.nextBytes(32), it.name, it.value) }
            .map { it.serialize() }
            .map { it.encodeToByteArray().encodeToString(Base64UrlStrict) }
        val disclosureDigests = disclosures
            .map { it.encodeToByteArray().toByteString().sha256().base64Url() }
        val jwsPayload = VerifiableCredentialSdJwt(
            subject = subjectId,
            notBefore = issuanceDate,
            issuer = identifier,
            expiration = expirationDate,
            jwtId = vcId,
            disclosureDigests = disclosureDigests,
            type = arrayOf(VcDataModelConstants.VERIFIABLE_CREDENTIAL, scheme.vcType),
            selectiveDisclosureAlgorithm = "sha-256",
            confirmationKey = subjectPublicKey.toJsonWebKey(),
            credentialStatus = credentialStatus,
        ).serialize().encodeToByteArray()
        // TODO Which content type to use for SD-JWT inside an JWS?
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
            ?: return Issuer.IssuedCredentialResult(
                failed = listOf(Issuer.FailedAttribute(scheme.vcType, RuntimeException("signing failed")))
            ).also { Napier.w("Could not wrap credential in SD-JWT") }
        val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~")

        return Issuer.IssuedCredentialResult(
            successful = listOf(Issuer.IssuedCredential.VcSdJwt(vcInSdJwt, scheme))
        )
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
            issuer = identifier,
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
        val bitset = KmmBitSet(REVOCATION_LIST_MIN_SIZE)
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
        return jwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)?.serialize()
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
