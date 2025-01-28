package at.asitplus.wallet.lib.rqes

import CscAuthorizationDetails
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.collection_entries.CscAuthParameter
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscDocumentDigest
import at.asitplus.rqes.collection_entries.CscKeyParameters
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.serializers.Base64X509CertificateSerializer
import at.asitplus.rqes.serializers.CscSignatureRequestParameterSerializer
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm.entries
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.PolymorphicSerializer
import kotlin.random.Random

class RqesOpenId4VpHolderTest : FreeSpec({

    val rawCert = """"MIIFajCCBPGgAwIBAgIQDNCovsYyz+ZF7KCpsIT7HDAKBggqhkjOPQQDAzBWMQsw
    CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTAwLgYDVQQDEydEaWdp
    Q2VydCBUTFMgSHlicmlkIEVDQyBTSEEzODQgMjAyMCBDQTEwHhcNMjMwMjE0MDAw
    MDAwWhcNMjQwMzE0MjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs
    aWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHVi
    LCBJbmMuMRMwEQYDVQQDEwpnaXRodWIuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D
    AQcDQgAEo6QDRgPfRlFWy8k5qyLN52xZlnqToPu5QByQMog2xgl2nFD1Vfd2Xmgg
    nO4i7YMMFTAQQUReMqyQodWq8uVDs6OCA48wggOLMB8GA1UdIwQYMBaAFAq8CCkX
    jKU5bXoOzjPHLrPt+8N6MB0GA1UdDgQWBBTHByd4hfKdM8lMXlZ9XNaOcmfr3jAl
    BgNVHREEHjAcggpnaXRodWIuY29tgg53d3cuZ2l0aHViLmNvbTAOBgNVHQ8BAf8E
    BAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGbBgNVHR8EgZMw
    gZAwRqBEoEKGQGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5
    YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5jcmwwRqBEoEKGQGh0dHA6Ly9jcmw0LmRp
    Z2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5j
    cmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3
    dy5kaWdpY2VydC5jb20vQ1BTMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGG
    GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2Nh
    Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTSHlicmlkRUNDU0hBMzg0MjAy
    MENBMS0xLmNydDAJBgNVHRMEAjAAMIIBgAYKKwYBBAHWeQIEAgSCAXAEggFsAWoA
    dwDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYZQ3Rv6AAAEAwBI
    MEYCIQDkFq7T4iy6gp+pefJLxpRS7U3gh8xQymmxtI8FdzqU6wIhALWfw/nLD63Q
    YPIwG3EFchINvWUfB6mcU0t2lRIEpr8uAHYASLDja9qmRzQP5WoC+p0w6xxSActW
    3SyB2bu/qznYhHMAAAGGUN0cKwAABAMARzBFAiAePGAyfiBR9dbhr31N9ZfESC5G
    V2uGBTcyTyUENrH3twIhAPwJfsB8A4MmNr2nW+sdE1n2YiCObW+3DTHr2/UR7lvU
    AHcAO1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61BcAAAGGUN0cOgAABAMA
    SDBGAiEAzOBr9OZ0+6OSZyFTiywN64PysN0FLeLRyL5jmEsYrDYCIQDu0jtgWiMI
    KU6CM0dKcqUWLkaFE23c2iWAhYAHqrFRRzAKBggqhkjOPQQDAwNnADBkAjAE3A3U
    3jSZCpwfqOHBdlxi9ASgKTU+wg0qw3FqtfQ31OwLYFdxh0MlNk/HwkjRSWgCMFbQ
    vMkXEPvNvv4t30K6xtpG26qmZ+6OiISBIIXMljWnsiYR1gyZnTzIg3AQSw4Vmw=="""".trimIndent().replace("\n", "")
        .replace("\r", "").replace(" ", "")

    val sampleCert = vckJsonSerializer.decodeFromString(
        Base64X509CertificateSerializer, rawCert
    )


    class DummyValueProvider {
        val viableSigAlg = listOf(
            X509SignatureAlgorithm.RS256,
            X509SignatureAlgorithm.RS384,
            X509SignatureAlgorithm.RS512,
            X509SignatureAlgorithm.ES256,
            X509SignatureAlgorithm.ES384,
            X509SignatureAlgorithm.ES512,
        )

        fun getSigningCredential(isValid: Boolean = false): CredentialInfo {
            val signatureAlgo = viableSigAlg.random()

            return CredentialInfo(
                credentialID = uuid4().toString(),
                signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                keyParameters = CscKeyParameters(
                    status = if (isValid) CscKeyParameters.KeyStatusOptions.ENABLED else CscKeyParameters.KeyStatusOptions.entries.random(),
                    algo = listOf(signatureAlgo.oid),
                    len = signatureAlgo.digest.outputLength.bits,
                    curve = if (signatureAlgo.isEc) signatureAlgo.algorithm.toJwsAlgorithm()
                        .getOrThrow().ecCurve!!.oid else null
                ),
                certParameters = CscCertificateParameters(
                    status = if (isValid) CscCertificateParameters.CertStatus.VALID else CscCertificateParameters.CertStatus.entries.random(),
                    certificates = listOf(sampleCert),
                    issuerDN = uuid4().toString(),
                    serialNumber = uuid4().toString(),
                    subjectDN = uuid4().toString(),
                ),
                authParameters = CscAuthParameter(
                    mode = CscAuthParameter.AuthMode.EXPLICIT,
                ),
                scal = CredentialInfo.ScalOptions.entries.random(),
                multisign = 1U,
                lang = "de"
            )
        }

        fun getDocumentDigests(): List<OAuthDocumentDigest> = (1..Random.nextInt(10)).map {
            OAuthDocumentDigest(
                hash = uuid4().bytes.encodeToString(Base64UrlStrict).decodeToByteArray(Base64UrlStrict),
                label = uuid4().toString(),
            )
        }
    }

    val dummyValueProvider = DummyValueProvider()
    val rqesWalletService = RqesOpenId4VpHolder()
    var newCredential: CredentialInfo

    fun CredentialInfo.isValid(): Boolean =
        this.keyParameters.status == CscKeyParameters.KeyStatusOptions.ENABLED && this.certParameters!!.status == CscCertificateParameters.CertStatus.VALID

    beforeEach {
        rqesWalletService.updateSignaturePropoerties(
            signatureFormat = SignatureFormat.entries.random(),
            conformanceLevel = ConformanceLevel.entries.random(),
        )
    }
    "RqesWalletService Tests" - {
        repeat(3) {
            "Certificates can be parsed" {
                newCredential = dummyValueProvider.getSigningCredential()
                val walletWithCredential =
                    kotlin.runCatching { rqesWalletService.setSigningCredential(newCredential) }.getOrNull()
                if (newCredential.isValid()) walletWithCredential shouldNotBe null
                else walletWithCredential shouldBe null
            }
        }

        val validCert = dummyValueProvider.getSigningCredential(isValid = true)
        val validSigningAlgo =
            validCert.keyParameters.algo.firstNotNullOf { oid -> catching { entries.first { it.oid == oid } }.getOrNull() }
        rqesWalletService.setSigningCredential(validCert)

        "CscAuthDetails respects SigningCredential" {
            val digests = dummyValueProvider.getDocumentDigests()
            val testAuthDetails = rqesWalletService.getCscAuthenticationDetails(digests, validSigningAlgo.digest)
            with(testAuthDetails as? CscAuthorizationDetails) {
                this shouldNotBe null
                this!!.credentialID shouldBe validCert.credentialID
                this.signatureQualifier shouldBe SignatureQualifier.EU_EIDAS_QES
                this.documentDigests.size shouldBe digests.size
                this.hashAlgorithmOid shouldBe validSigningAlgo.digest.oid
            }
            val serialized =
                vckJsonSerializer.encodeToString(PolymorphicSerializer(AuthorizationDetails::class), testAuthDetails)
            val deserialized =
                vckJsonSerializer.decodeFromString(PolymorphicSerializer(AuthorizationDetails::class), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe testAuthDetails
        }

        "CscDocumentDigest respects SigningCredential" {
            val digests = dummyValueProvider.getDocumentDigests()
            val testDocumentDigests = rqesWalletService.getCscDocumentDigests(
                digests,
                rqesWalletService.signingCredential!!.supportedSigningAlgorithms.first()
            )
            with(testDocumentDigests as? CscDocumentDigest) {
                this shouldNotBe null
                this!!.signAlgoOid shouldBe validSigningAlgo.oid
                // These change before each test
                this.signatureFormat shouldBe rqesWalletService.signatureProperties.signatureFormat
                this.conformanceLevel shouldBe rqesWalletService.signatureProperties.conformanceLevel
                this.signedEnvelopeProperty shouldBe rqesWalletService.signatureProperties.signedEnvelopeProperty
            }
            val serialized = vckJsonSerializer.encodeToString(CscDocumentDigest.serializer(), testDocumentDigests)
            val deserialized = vckJsonSerializer.decodeFromString(CscDocumentDigest.serializer(), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe testDocumentDigests
        }

        "AuthenticationRequest SERVICE" {
            val request = rqesWalletService.createServiceAuthenticationRequest()
            request.credentialID shouldBe null
            request.signatureQualifier shouldBe null
            request.numSignatures shouldBe null

            val serialized = vckJsonSerializer.encodeToString(AuthenticationRequestParameters.serializer(), request)
            val deserialized =
                vckJsonSerializer.decodeFromString(AuthenticationRequestParameters.serializer(), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe request
        }

        "AuthenticationRequest CREDENTIAL" {
            val documentDigests = dummyValueProvider.getDocumentDigests()
            val request = rqesWalletService.createCredentialAuthenticationRequest(
                documentDigests = documentDigests,
                redirectUrl = "someOtherURL",
                hashAlgorithm = Digest.entries.random(),
                numSignatures = 1,
                hashes = listOf(uuid4().bytes),
                optionalParameters = null
            )
            request.credentialID?.encodeToString(Base64UrlStrict) shouldBe validCert.credentialID

            request.signatureQualifier shouldBe SignatureQualifier.EU_EIDAS_QES
            request.numSignatures shouldNotBe null
            request.redirectUrl shouldBe "someOtherURL"
            request.authorizationDetails shouldNotBe null

            request.authorizationDetails?.onEach {
                with(it as? CscAuthorizationDetails) {
                    this shouldNotBe null
                    this?.documentDigests shouldBe documentDigests
                }
            }

            val serialized = vckJsonSerializer.encodeToString(AuthenticationRequestParameters.serializer(), request)
            val deserialized =
                vckJsonSerializer.decodeFromString(AuthenticationRequestParameters.serializer(), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe request
        }

        "TokenRequest" {
            val documentDigests = dummyValueProvider.getDocumentDigests()
            val request = rqesWalletService.createOAuth2TokenRequest(
                state = uuid4().toString(),
                authorization = OAuth2Client.AuthorizationForToken.Code(uuid4().toString()),
                authorizationDetails = setOf(
                    rqesWalletService.getCscAuthenticationDetails(
                        documentDigests,
                        Digest.entries.random(),
                    )
                )
            )

            request.authorizationDetails shouldNotBe null

            val serialized = vckJsonSerializer.encodeToString(TokenRequestParameters.serializer(), request)
            val deserialized = vckJsonSerializer.decodeFromString(TokenRequestParameters.serializer(), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe request
        }

        "SignHash" {
            val request = rqesWalletService.createSignHashRequestParameters(
                dtbsr = listOf(uuid4().bytes),
                sad = uuid4().toString(),
                signatureAlgorithm = rqesWalletService.signingCredential!!.supportedSigningAlgorithms.first(),
            )

            with(request as? SignHashParameters) {
                this shouldNotBe null
                this!!.credentialId shouldBe validCert.credentialID
                this.signAlgoOid shouldBe validSigningAlgo.oid
            }
            val serialized = vckJsonSerializer.encodeToString(CscSignatureRequestParameterSerializer, request)
            val deserialized = vckJsonSerializer.decodeFromString(CscSignatureRequestParameterSerializer, serialized)
            deserialized shouldNotBe null
            deserialized shouldBe request
        }

    }
})