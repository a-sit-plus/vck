package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.BitSet
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.DataSourceProblem
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
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
    private val validator: Validator,
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val revocationListBaseUrl: String = "https://wallet.a-sit.at/backend/credentials/status",
    private val zlibService: ZlibService = DefaultZlibService(),
    private val revocationListLifetime: Duration = 48.hours,
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val clock: Clock = Clock.System,
    override val keyMaterial: KeyMaterial,
    override val cryptoAlgorithms: Set<SignatureAlgorithm> = setOf(keyMaterial.signatureAlgorithm),
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
    /**
     * The identifier used in `issuer` properties of issued credentials.
     * Note that for SD-JWT VC this must be a URI. */
    private val identifier: String = keyMaterial.identifier,
) : Issuer {

    constructor(
        keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
        issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
        validator: Validator = Validator(),
        identifier: String = keyMaterial.identifier,
    ) : this(
        validator = validator,
        issuerCredentialStore = issuerCredentialStore,
        jwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
        coseService = DefaultCoseService(DefaultCryptoService(keyMaterial)),
        keyMaterial = keyMaterial,
        cryptoAlgorithms = setOf(keyMaterial.signatureAlgorithm),
        identifier = identifier,
    )

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
        issuanceDate: Instant
    ): Issuer.IssuedCredential {
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.Iso(credential.issuerSignedItems, credential.scheme),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod,
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")
        val deviceKeyInfo = DeviceKeyInfo(credential.subjectPublicKey.toCoseKey().getOrElse { ex ->
            Napier.w("Could not transform SubjectPublicKey to COSE Key", ex)
            throw DataSourceProblem("SubjectPublicKey transformation failed", ex.message, ex)
        })
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
            )
        )
        val issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = mapOf(credential.scheme.isoNamespace!! to credential.issuerSignedItems),
            issuerAuth = coseService.createSignedCose(
                payload = mso,
                addKeyId = false,
                addCertificate = true,
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
            credential = IssuerCredentialStore.Credential.VcJwt(vcId, credential.subject, credential.scheme),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)
        val vc = VerifiableCredential(
            id = vcId,
            issuer = identifier,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            credentialStatus = credentialStatus,
            credentialSubject = credential.subject,
            credentialType = credential.scheme.vcType!!,
        )

        val vcInJws = wrapVcInJws(vc)
            ?: throw RuntimeException("Signing failed")
        return Issuer.IssuedCredential.VcJwt(vcInJws, credential.scheme)
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        issuanceDate: Instant
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val subjectId = credential.subjectPublicKey.didEncoded
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcSd(vcId, credential.claims, credential.scheme),
            subjectPublicKey = credential.subjectPublicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = timePeriod
        ) ?: throw IllegalArgumentException("No statusListIndex from issuerCredentialStore")

        val credentialStatus = CredentialStatus(getRevocationListUrlFor(timePeriod), statusListIndex)
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
            selectiveDisclosureAlgorithm = "sha-256",
            confirmationClaim = cnf,
            credentialStatus = credentialStatus,
        )
        val vcSdJwtObject = vckJsonSerializer.encodeToJsonElement(vcSdJwt).jsonObject
        val entireObject = buildJsonObject {
            vcSdJwtObject.forEach {
                put(it.key, it.value)
            }
            sdJwt.forEach {
                put(it.key, it.value)
            }
        }
        val jws = jwsService.createSignedJwt(JwsContentTypeConstants.SD_JWT, entireObject, JsonObject.serializer())
            .getOrElse {
                Napier.w("Could not wrap credential in SD-JWT", it)
                throw RuntimeException("Signing failed", it)
            }
        val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
        Napier.i("issueVcSd: $vcInSdJwt")
        return Issuer.IssuedCredential.VcSdJwt(vcInSdJwt, credential.scheme)
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

    private suspend fun wrapVcInJws(vc: VerifiableCredential): String? =
        jwsService.createSignedJwt(JwsContentTypeConstants.JWT, vc.toJws(), VerifiableCredentialJws.serializer())
            .getOrElse {
                Napier.w("Could not wrapVcInJws", it)
                return null
            }.serialize()

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
