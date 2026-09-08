@file:OptIn(ExperimentalUuidApi::class)

package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMeta
import at.asitplus.etsi.relyingParty.WrpLangString
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpStatus
import at.asitplus.etsi.relyingParty.WrpStatusList
import at.asitplus.etsi.relyingParty.WrpSupervisoryAuthority
import at.asitplus.iso.sha256
import at.asitplus.openid.VerifierInfo
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestValidationData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidationResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidationResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random
import kotlin.time.Clock.System
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

const val CA_NAME = "MS Root CA"
const val WRPAC_PROVIDER_NAME = "WRPAC Provider"
const val WRPRC_PROVIDER_NAME = "WRPRC Provider"
const val WRP_NAME = "WRP Demo Service"
const val DEFAULT_DOCTYPE = "eu.europa.ec.eudi.pid.1"
const val WRPRC_JWS_TYPE = "rc-wrp+jwt"
const val REGISTRATION_CERT_FORMAT = "registration_cert"

val OID_ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")
val OID_SERIAL_NUMBER = ObjectIdentifier("2.5.4.5")

suspend fun issueWrpAccessCertificate(
    issuer: KeyMaterial,
    issuerName: String,
    subjectName: String,
    wrpacIdentifier: WrpacIdentifier,
    subjectPublicKey: EphemeralKeyWithoutCert,
    validity: Duration,
): X509Certificate {
    val oid = when (wrpacIdentifier) {
        is WrpacIdentifier.WrpacLegalIdentifier -> OID_ORGANIZATION_IDENTIFIER
        is WrpacIdentifier.WrpacNaturalIdentifier -> OID_SERIAL_NUMBER
    }
    val algorithm = issuer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
    val notBefore = System.now().truncateToSeconds()
    val tbsCertificate = TbsCertificate(
        version = 2,
        serialNumber = Random.nextBytes(8),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(issuerName)))),
        subjectName = listOf(
            RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(subjectName))),
            RelativeDistinguishedName(
                AttributeTypeAndValue.Other(oid, Asn1String.UTF8(wrpacIdentifier.identifier)),
            ),
        ),
        validFrom = Asn1Time(notBefore),
        validUntil = Asn1Time((notBefore + validity).truncateToSeconds()),
        signatureAlgorithm = algorithm,
        publicKey = subjectPublicKey.publicKey,
        extensions = listOf(),
    )
    val signature = issuer.sign(tbsCertificate.encodeToDer()).asKmmResult().getOrThrow()
    return X509Certificate(tbsCertificate, algorithm, signature)
}

data class WrpFixture(
    val trustAnchors: List<X509Certificate>,
    val wrpIdentifier: String,
    val wrpacChain: List<X509Certificate>,
    val clientId: String,
    val wrprcSigningKeyMaterial: KeyMaterial,
)

suspend fun buildWrpFixture(
    wrpIdentifier: String = Uuid.generateV4().toString(),
    wrpacIdentifier: WrpacIdentifier? = WrpacIdentifier.WrpacLegalIdentifier(wrpIdentifier),
    validity: Duration = 30.days,
): WrpFixture {
    val rootKey = EphemeralKeyWithoutCert()
    val root = TestCertificateAuthority(name = CA_NAME, key = rootKey)
    val trustAnchors = listOf(root.certificate())

    val wrpacProviderKey = EphemeralKeyWithoutCert()
    val wrpacProvider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = wrpacProviderKey)
    val wrpacProviderCert = root.issue(
        subjectName = WRPAC_PROVIDER_NAME,
        validity = validity,
        key = wrpacProviderKey,
    ).getCertificate()!!

    val wrpKey = EphemeralKeyWithoutCert()
    val wrpCert = if (wrpacIdentifier != null) {
        issueWrpAccessCertificate(
            issuer = wrpacProviderKey,
            issuerName = WRPAC_PROVIDER_NAME,
            subjectName = WRP_NAME,
            wrpacIdentifier = wrpacIdentifier,
            subjectPublicKey = wrpKey,
            validity = validity,
        )
    } else {
        wrpacProvider.issue(subjectName = WRP_NAME, validity = validity, key = wrpKey).getCertificate()!!
    }
    val wrpacChain = listOf(wrpCert, wrpacProviderCert)
    val clientId = "x509_hash:${wrpacChain.leaf.encodeToDer().sha256().encodeToString(Base64UrlStrict)}"

    val wrprcProviderKey = EphemeralKeyWithoutCert()
    val wrprcSigningKeyMaterial = root.issue(
        subjectName = WRPRC_PROVIDER_NAME,
        validity = validity,
        key = wrprcProviderKey,
    )

    return WrpFixture(trustAnchors, wrpIdentifier, wrpacChain, clientId, wrprcSigningKeyMaterial)
}

fun WrpFixture.validateWrpac(): WrpacValidationResult? = WrpacValidator.validate(
    validationData = WrpRequestValidationData(clientId = clientId, certificateChain = wrpacChain),
    certificateTrustAnchors = trustAnchors,
)

fun defaultMdocCredential(
    doctypeValue: String = DEFAULT_DOCTYPE,
    claimNames: List<String> = listOf("given_name", "family_name", "birth_date"),
): WrpCredential = WrpCredential(
    format = "mso_mdoc",
    meta = WrpCredentialMeta(doctypeValue = doctypeValue),
    claim = claimNames.map { WrpClaim(path = listOf(doctypeValue, it)) },
)

fun buildWrpPayload(
    wrpIdentifier: String,
    name: String? = WRP_NAME,
    intendedUseId: String? = "urn:uuid:${Uuid.generateV4()}",
    credentials: List<WrpCredential> = listOf(defaultMdocCredential()),
    iat: Long = System.now().epochSeconds,
    exp: Long? = (System.now() + 30.days).epochSeconds,
    statusListIdx: Int = 0,
    statusListUri: String = "https://localhost/statuslists/1",
): WrpPayload = WrpPayload(
    name = name,
    subLn = "Demo Service",
    sub = wrpIdentifier,
    country = "AT",
    registryUri = "https://localhost/wrp",
    srvDescription = listOf(listOf(WrpLangString(lang = "en", value = "Service description"))),
    entitlements = listOf("access-service"),
    privacyPolicy = "https://localhost/privacy",
    infoUri = "",
    supportUri = "https://localhost/support",
    supervisoryAuthority = WrpSupervisoryAuthority(),
    certificatePolicy = "https://localhost/certificate-policy",
    iat = iat,
    exp = exp,
    status = WrpStatus(statusList = WrpStatusList(idx = statusListIdx, uri = statusListUri)),
    purpose = listOf(WrpLangString(lang = "en", value = "Purpose description.")),
    credentials = credentials,
    intendedUseId = intendedUseId,
    providesAttestations = emptyList(),
    publicBody = false,
)

suspend fun signWrprc(
    keyMaterial: KeyMaterial,
    payload: WrpPayload,
    type: String = WRPRC_JWS_TYPE,
): String = SignJwt<WrpPayload>(keyMaterial, JwsHeaderCertOrJwk())(
    type = type,
    payload = payload,
    serializer = WrpPayload.serializer(),
).getOrThrow().toString()

fun mdocDcqlRequest(
    doctypeValue: String = DEFAULT_DOCTYPE,
    claimNames: List<String> = listOf("given_name", "family_name", "birth_date"),
): CredentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
    DCQLQuery(
        credentials = DCQLCredentialQueryList(
            nonEmptyListOf(
                DCQLIsoMdocCredentialQuery(
                    id = DCQLCredentialQueryIdentifier(Uuid.generateV4().toHexString()),
                    meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(doctypeValue = doctypeValue),
                    claims = DCQLClaimsQueryList(
                        list = claimNames.map {
                            DCQLIsoMdocClaimsQuery(
                                path = DCQLClaimsPathPointer(
                                    nonEmptyListOf(
                                        NameSegment(doctypeValue),
                                        NameSegment(it)
                                    )
                                ),
                            )
                        }.toNonEmptyList(),
                    ),
                ),
            ),
        ),
    ),
)

fun sdJwtDcqlRequest(
    vctValue: String,
    claimNames: List<String> = listOf("given_name"),
): CredentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
    DCQLQuery(
        credentials = DCQLCredentialQueryList(
            nonEmptyListOf(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier(Uuid.generateV4().toHexString()),
                    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(vctValue)),
                    claims = DCQLClaimsQueryList(
                        list = claimNames.map {
                            DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(nonEmptyListOf(NameSegment(it))))
                        }.toNonEmptyList(),
                    ),
                ),
            ),
        ),
    ),
)

suspend fun WrpFixture.validateWrprc(
    payload: WrpPayload,
    request: CredentialPresentationRequest? = mdocDcqlRequest(),
    signingKeyMaterial: KeyMaterial = wrprcSigningKeyMaterial,
    verifierInfoFormat: String = REGISTRATION_CERT_FORMAT,
    jwsType: String = WRPRC_JWS_TYPE,
    revokedStatusIndex: Int = 1,
    accessCertValidation: WrpacValidationResult? = null,
): WrprcValidationResult? {
    val wrprcJws = signWrprc(signingKeyMaterial, payload, type = jwsType)
    val validationData = WrpRequestValidationData(
        clientId = clientId,
        certificateChain = wrpacChain,
        verifierInfo = nonEmptyListOf(VerifierInfo(format = verifierInfoFormat, data = wrprcJws)),
        request = request,
    )
    val resolvedAccessCertValidation = accessCertValidation ?: validateWrpac()!!
    val statusListTokenResolver = StatusListTokenResolver { statusListUrl ->
        buildStatusListToken(statusListUrl, revokedIndex = revokedStatusIndex)
    }
    return WrprcValidator.validate(
        accessCertValidation = resolvedAccessCertValidation,
        validationData = validationData,
        statusListTokenResolver = statusListTokenResolver,
        certificateTrustAnchors = trustAnchors,
    )
}

/** Status list token for [statusListUrl], with only [revokedIndex] set to [TokenStatus.Invalid]. */
suspend fun buildStatusListToken(
    statusListUrl: UniformResourceIdentifier,
    revokedIndex: Int,
) = StatusListJwt(
    value = SignJwt<StatusListTokenPayload>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())(
        type = MediaTypes.STATUSLIST_JWT,
        payload = StatusListTokenPayload(
            subject = statusListUrl,
            issuedAt = System.now(),
            revocationList = StatusListView.fromTokenStatuses(
                tokenStatuses = List(revokedIndex + 1) {
                    if (it == revokedIndex) TokenStatus.Invalid else TokenStatus.Valid
                },
                statusBitSize = TokenStatusBitSize.ONE,
            ).toStatusList(DefaultZlibService(), null),
        ),
        serializer = StatusListTokenPayload.serializer(),
    ).getOrThrow(),
    resolvedAt = System.now(),
)
