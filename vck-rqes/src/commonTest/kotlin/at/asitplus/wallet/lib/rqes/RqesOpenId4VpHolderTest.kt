package at.asitplus.wallet.lib.rqes

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.qes.CscAuthorizationDetails
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.QtspSignatureRequest
import at.asitplus.rqes.SignHashRequestParameters
import at.asitplus.rqes.collection_entries.CertificateParameters
import at.asitplus.rqes.collection_entries.DocumentDigest
import at.asitplus.rqes.collection_entries.KeyParameters
import at.asitplus.rqes.enums.SignatureQualifier
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.rqes.helper.DummyValueProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class RqesOpenId4VpHolderTest : FreeSpec({

    val dummyValueProvider = DummyValueProvider()
    val rqesWalletService = RqesOpenId4VpHolder(
        oauth2Client = OAuth2Client(signPushedAuthorizationRequest = null)
    )

    fun CredentialInfo.isValid(): Boolean =
        keyParameters.status == KeyParameters.KeyStatusOptions.ENABLED
                && certParameters!!.status == CertificateParameters.CertStatus.VALID

    beforeEach {
        rqesWalletService.updateSignatureProperties(
            signatureFormat = SignatureFormat.entries.random(),
            conformanceLevel = ConformanceLevel.entries.random(),
        )
    }
    "RqesWalletService Tests" - {
        repeat(10) {
            "random certificate can be parsed" {
                dummyValueProvider.getSigningCredential().also {
                    if (it.isValid()) {
                        rqesWalletService.setSigningCredential(it)
                    } else {
                        shouldThrow<IllegalArgumentException> { rqesWalletService.setSigningCredential(it) }
                    }
                }
            }
        }

        "certificate without certParameters is invalid" {
            dummyValueProvider.getSigningCredential(true).copy(
                certParameters = null
            ).apply {
                shouldThrow<IllegalArgumentException> { rqesWalletService.setSigningCredential(this) }
            }
        }

        "certificate without status is valid" {
            dummyValueProvider.getSigningCredential(true).copy(
                certParameters = CertificateParameters(
                    status = null,
                    certificates = listOf(EphemeralKeyWithSelfSignedCert().getCertificate()!!),
                    issuerDN = uuid4().toString(),
                    serialNumber = uuid4().toString(),
                    subjectDN = uuid4().toString(),
                ),
            ).apply {
                rqesWalletService.setSigningCredential(this)
            }
        }

        "certificate without certparameters is invalid" {
            dummyValueProvider.getSigningCredential(true).copy(
                certParameters = dummyValueProvider.getSigningCredential(true).certParameters!!.copy(certificates = null)
            ).apply {
                shouldThrow<IllegalArgumentException> { rqesWalletService.setSigningCredential(this) }
            }
        }

        val validCert = dummyValueProvider.getSigningCredential(isValid = true)
        val validSigningAlgo =
            validCert.keyParameters.algo.firstNotNullOf { oid -> catchingUnwrapped { X509SignatureAlgorithm.entries.first { it.oid == oid } }.getOrNull() }
        rqesWalletService.setSigningCredential(validCert)

        "CscAuthDetails respects SigningCredential" {
            val digests = dummyValueProvider.buildDocumentDigests()
            val authDetails = rqesWalletService.getCscAuthenticationDetails(digests, validSigningAlgo.digest)
            authDetails.shouldBeInstanceOf<CscAuthorizationDetails>().apply {
                this.credentialID shouldBe validCert.credentialID
                this.signatureQualifier shouldBe SignatureQualifier.EU_EIDAS_QES
                this.documentDigests.size shouldBe digests.size
                this.hashAlgorithmOid shouldBe validSigningAlgo.digest.oid
            }
            val serialized = vckJsonSerializer.encodeToString(authDetails)
            vckJsonSerializer.decodeFromString<CscAuthorizationDetails>(serialized)
                .shouldBe(authDetails)
        }

        "CscDocumentDigest respects SigningCredential" {
            val digests = dummyValueProvider.buildDocumentDigests()
            val testDocumentDigests = rqesWalletService.getCscDocumentDigests(
                digests,
                rqesWalletService.signingCredential!!.supportedSigningAlgorithms.first()
            )
            with(testDocumentDigests) {
                this shouldNotBe null
                this.signAlgoOid shouldBe validSigningAlgo.oid
                // These change before each test
                this.signatureFormat shouldBe rqesWalletService.signatureProperties.signatureFormat
                this.conformanceLevel shouldBe rqesWalletService.signatureProperties.conformanceLevel
                this.signedEnvelopeProperty shouldBe rqesWalletService.signatureProperties.signedEnvelopeProperty
            }
            val serialized = vckJsonSerializer.encodeToString(DocumentDigest.serializer(), testDocumentDigests)
            val deserialized = vckJsonSerializer.decodeFromString(DocumentDigest.serializer(), serialized)
            deserialized shouldNotBe null
            deserialized shouldBe testDocumentDigests
        }

        "AuthenticationRequest SERVICE" {
            val request = rqesWalletService.createServiceAuthenticationRequest()
            request.credentialID shouldBe null
            request.signatureQualifier shouldBe null
            request.numSignatures shouldBe null

            val serialized = vckJsonSerializer.encodeToString(request)
            vckJsonSerializer.decodeFromString<AuthenticationRequestParameters>(serialized)
                .shouldBe(request)
        }

        "AuthenticationRequest CREDENTIAL" {
            val documentDigests = dummyValueProvider.buildDocumentDigests()
            val request = rqesWalletService.createCredentialAuthenticationRequest(
                documentDigests = documentDigests,
                redirectUrl = "someOtherURL",
                hashAlgorithm = Digest.entries.random(),
                optionalParameters = null
            )

            request.redirectUrl shouldBe "someOtherURL"
            request.authorizationDetails.shouldNotBeNull().forEach {
                it.shouldBeInstanceOf<CscAuthorizationDetails>()
                it.documentDigests shouldBe documentDigests
            }

            val serialized = vckJsonSerializer.encodeToString(request)
            vckJsonSerializer.decodeFromString<AuthenticationRequestParameters>(serialized)
                .shouldBe(request)
        }

        "TokenRequest" {
            val request = rqesWalletService.createOAuth2TokenRequest(
                state = uuid4().toString(),
                authorization = OAuth2Client.AuthorizationForToken.Code(uuid4().toString()),
                authorizationDetails = setOf(
                    rqesWalletService.getCscAuthenticationDetails(
                        dummyValueProvider.buildDocumentDigests(),
                        Digest.entries.random(),
                    )
                )
            )
            request.authorizationDetails shouldNotBe null

            val serialized = vckJsonSerializer.encodeToString(request)
            vckJsonSerializer.decodeFromString<TokenRequestParameters>(serialized)
                .shouldBe(request)
        }

        "SignHash" {
            val request = rqesWalletService.createSignHashRequestParameters(
                dtbsr = listOf(uuid4().bytes),
                sad = uuid4().toString(),
                signatureAlgorithm = rqesWalletService.signingCredential!!.supportedSigningAlgorithms.first(),
            ).shouldBeInstanceOf<SignHashRequestParameters>()

            request.credentialId shouldBe validCert.credentialID
            request.signAlgoOid shouldBe validSigningAlgo.oid

            val serialized = vckJsonSerializer.encodeToString(request)
            vckJsonSerializer.decodeFromString<QtspSignatureRequest>(serialized)
                .shouldBe(request)
        }
    }
})

val X509SignatureAlgorithm.digest: Digest
    get() = when (this) {
        is X509SignatureAlgorithm.ECDSA -> digest
        is X509SignatureAlgorithm.RSAPSS -> digest
        is X509SignatureAlgorithm.RSAPKCS1 -> digest
    }