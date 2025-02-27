package at.asitplus.wallet.lib.rqes

import CscAuthorizationDetails
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.QtspSignatureRequest
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.collection_entries.CertificateParameters
import at.asitplus.rqes.collection_entries.DocumentDigest
import at.asitplus.rqes.collection_entries.KeyParameters
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm.entries
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToString

class RqesOpenId4VpHolderTest : FreeSpec({

    val dummyValueProvider = DummyValueProvider()
    val rqesWalletService = RqesOpenId4VpHolder()

    fun CredentialInfo.isValid(): Boolean =
        this.keyParameters.status == KeyParameters.KeyStatusOptions.ENABLED && this.certParameters!!.status == CertificateParameters.CertStatus.VALID

    beforeEach {
        rqesWalletService.updateSignatureProperties(
            signatureFormat = SignatureFormat.entries.random(),
            conformanceLevel = ConformanceLevel.entries.random(),
        )
    }
    "RqesWalletService Tests" - {
        repeat(3) {
            "Certificates can be parsed" {
                val newCredential = dummyValueProvider.getSigningCredential()
                val walletWithCredential =
                    kotlin.runCatching { rqesWalletService.setSigningCredential(newCredential) }.getOrNull()
                if (newCredential.isValid()) {
                    walletWithCredential shouldNotBe null
                } else {
                    walletWithCredential shouldBe null
                }
            }
        }

        val validCert = dummyValueProvider.getSigningCredential(isValid = true)
        val validSigningAlgo =
            validCert.keyParameters.algo.firstNotNullOf { oid -> catching { entries.first { it.oid == oid } }.getOrNull() }
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
            ).shouldBeInstanceOf<SignHashParameters>()

            request.credentialId shouldBe validCert.credentialID
            request.signAlgoOid shouldBe validSigningAlgo.oid

            val serialized = vckJsonSerializer.encodeToString(request)
            vckJsonSerializer.decodeFromString<QtspSignatureRequest>(serialized)
                .shouldBe(request)
        }
    }
})