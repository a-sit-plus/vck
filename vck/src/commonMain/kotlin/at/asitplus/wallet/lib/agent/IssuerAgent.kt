package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.cbor.*
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.jws.*
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
 * An agent that implements [Issuer], i.e. it issues credentials for other agents.
 *
 * For backwards compatibility, this also implements [StatusListIssuer], but this should be separated.
 */
class IssuerAgent(
    override val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    @Deprecated("Removed, see `StatusListAgent`")
    private val validator: Validator = Validator(),
    private val issuerCredentialStore: IssuerCredentialStore = InMemoryIssuerCredentialStore(),
    private val statusListBaseUrl: String = "https://wallet.a-sit.at/backend/credentials/status",
    @Deprecated("Removed, see `StatusListAgent`")
    private val statusListAggregationUrl: String? = null,
    @Deprecated("Removed, see `StatusListAgent`")
    private val zlibService: ZlibService = DefaultZlibService(),
    @Deprecated("Removed, see `StatusListAgent`")
    private val revocationListLifetime: Duration = 48.hours,
    private val clock: Clock = Clock.System,
    override val cryptoAlgorithms: Set<SignatureAlgorithm> = setOf(keyMaterial.signatureAlgorithm),
    private val timePeriodProvider: TimePeriodProvider = FixedTimePeriodProvider,
    /** The identifier used in `issuer` properties of issued credentials. Note that for SD-JWT VC this must be a URI. */
    private val identifier: String = keyMaterial.identifier,
    private val signIssuedSdJwt: SignJwtFun<JsonObject> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signIssuedVc: SignJwtFun<VerifiableCredentialJws> = SignJwt(keyMaterial, JwsHeaderKeyId()),
    @Deprecated("Removed, see `StatusListAgent`")
    private val signStatusListJwt: SignJwtFun<StatusListTokenPayload> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signMobileSecurityObject: SignCoseFun<MobileSecurityObject> =
        SignCose(keyMaterial, CoseHeaderNone(), CoseHeaderCertificate()),
    @Deprecated("Removed, see `StatusListAgent`")
    private val signStatusListCwt: SignCoseFun<StatusListTokenPayload> =
        SignCose(keyMaterial, CoseHeaderKeyId(), CoseHeaderCertificate()),
) : Issuer,
    // TODO Remove > 5.8.0
    StatusListIssuer by StatusListAgent(
        keyMaterial = keyMaterial,
        validator = validator,
        issuerCredentialStore = issuerCredentialStore,
        statusListBaseUrl = statusListBaseUrl,
        statusListAggregationUrl = statusListAggregationUrl,
        zlibService = zlibService,
        revocationListLifetime = revocationListLifetime,
        clock = clock,
        timePeriodProvider = timePeriodProvider,
        signStatusListJwt = signStatusListJwt,
        signStatusListCwt = signStatusListCwt,
    ) {

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
        val reference = issuerCredentialStore.createStatusListIndex(credential, timePeriod).getOrThrow()
        val coseKey = credential.subjectPublicKey.toCoseKey()
            .onFailure { Napier.w("issueMdoc error", it) }
            .getOrThrow()
        val deviceKeyInfo = DeviceKeyInfo(coseKey)
        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = reference.statusListIndex,
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
                protectedHeader = null,
                unprotectedHeader = null,
                payload = mso,
                serializer = MobileSecurityObject.serializer(),
            ).getOrThrow(),
        )
        Napier.i("issueMdoc: $issuerSigned")
        return Issuer.IssuedCredential.Iso(
            issuerSigned = issuerSigned,
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo
        ).also {
            issuerCredentialStore.updateStoredCredential(reference, it).getOrThrow()
        }
    }

    private suspend fun issueVc(
        credential: CredentialToBeIssued.VcJwt,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val reference = issuerCredentialStore.createStatusListIndex(credential, timePeriod).getOrThrow()
        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = reference.statusListIndex,
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
            type = JwsContentTypeConstants.JWT,
            payload = vc.toJws(),
            serializer = VerifiableCredentialJws.serializer(),
        ).onFailure {
            Napier.w("issueVc error", it)
        }.getOrThrow()
        Napier.i("issueVc: $vcInJws")
        return Issuer.IssuedCredential.VcJwt(
            vc = vc,
            signedVcJws = vcInJws,
            vcJws = vcInJws.serialize(),
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo,
        ).also {
            issuerCredentialStore.updateStoredCredential(reference, it).getOrThrow()
        }
    }

    private suspend fun issueVcSd(
        credential: CredentialToBeIssued.VcSd,
        issuanceDate: Instant,
    ): Issuer.IssuedCredential {
        val vcId = "urn:uuid:${uuid4()}"
        val expirationDate = credential.expiration
        val timePeriod = timePeriodProvider.getTimePeriodFor(issuanceDate)
        val subjectId = credential.subjectPublicKey.didEncoded
        val reference = issuerCredentialStore.createStatusListIndex(credential, timePeriod).getOrThrow()
        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = reference.statusListIndex,
                uri = UniformResourceIdentifier(getRevocationListUrlFor(timePeriod)),
            )
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
        ).onFailure {
            Napier.w("issueVcSd error", it)
        }.getOrThrow()
        val sdJwtSigned = SdJwtSigned.issued(jws, disclosures.toList())
        Napier.i("issueVcSd: $sdJwtSigned")
        return Issuer.IssuedCredential.VcSdJwt(
            sdJwtVc = vcSdJwt,
            signedSdJwtVc = sdJwtSigned,
            vcSdJwt = sdJwtSigned.serialize(),
            scheme = credential.scheme,
            subjectPublicKey = credential.subjectPublicKey,
            userInfo = credential.userInfo,
        ).also {
            issuerCredentialStore.updateStoredCredential(reference, it).getOrThrow()
        }
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

}
