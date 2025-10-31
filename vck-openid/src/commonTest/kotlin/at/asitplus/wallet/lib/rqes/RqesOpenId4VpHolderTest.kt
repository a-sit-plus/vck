package at.asitplus.wallet.lib.rqes

import at.asitplus.catchingUnwrapped
import at.asitplus.csc.QtspSignatureRequest
import at.asitplus.csc.SignHashRequestParameters
import at.asitplus.csc.collection_entries.CertificateParameters
import at.asitplus.csc.collection_entries.DocumentDigest
import at.asitplus.csc.collection_entries.KeyParameters
import at.asitplus.csc.enums.ConformanceLevel
import at.asitplus.csc.enums.SignatureFormat
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CscAuthorizationDetails
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.rqes.helper.DummyValueProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

val RqesOpenId4VpHolderTest by testSuite {

    val dummyValueProvider = DummyValueProvider()
    val rqesWalletService = RqesWalletService(
        oauth2Client = OAuth2Client(signPushedAuthorizationRequest = null)
    )

    var signatureProperties = RqesWalletService.SignatureProperties()
    var validCert = runBlocking { dummyValueProvider.getCredentialInfo() }
    var validSigningAlgo =
        validCert.keyParameters.algo.shuffled()
            .firstNotNullOf { oid -> catchingUnwrapped { X509SignatureAlgorithm.entries.first { it.oid == oid } }.getOrNull() }

    testConfig = TestConfig.aroundEach {
        signatureProperties = signatureProperties.copy(
            signatureFormat = SignatureFormat.entries.random(),
            conformanceLevel = ConformanceLevel.entries.random(),
        )
        validCert = runBlocking { dummyValueProvider.getCredentialInfo() }
        validSigningAlgo =
            validCert.keyParameters.algo.shuffled()
                .firstNotNullOf { oid -> catchingUnwrapped { X509SignatureAlgorithm.entries.first { it.oid == oid } }.getOrNull() }

        it()
    }

    "Invalid signing certificate throws" {
        dummyValueProvider.getCredentialInfo(
            CertificateParameters.CertStatus.VALID,
            KeyParameters.KeyStatusOptions.DISABLED
        ).let {
            shouldThrow<IllegalArgumentException> { it.toSigningCredential() }
        }

        dummyValueProvider.getCredentialInfo(
            CertificateParameters.CertStatus.EXPIRED,
            KeyParameters.KeyStatusOptions.ENABLED
        ).let {
            shouldThrow<IllegalArgumentException> { it.toSigningCredential() }
        }

        dummyValueProvider.getCredentialInfo(
            CertificateParameters.CertStatus.REVOKED,
            KeyParameters.KeyStatusOptions.ENABLED
        ).let {
            shouldThrow<IllegalArgumentException> { it.toSigningCredential() }
        }

        dummyValueProvider.getCredentialInfo(
            CertificateParameters.CertStatus.SUSPENDED,
            KeyParameters.KeyStatusOptions.ENABLED
        ).let {
            shouldThrow<IllegalArgumentException> { it.toSigningCredential() }
        }
    }

    "certificate without certParameters is invalid" {
        validCert.copy(
            certParameters = null
        ).apply {
            shouldThrow<IllegalArgumentException> { this.toSigningCredential() }
        }
    }

    "certificate without status is valid" {
        validCert.copy(
            certParameters = CertificateParameters(
                status = null,
                certificates = listOf(EphemeralKeyWithSelfSignedCert().getCertificate()!!),
                issuerDN = uuid4().toString(),
                serialNumber = uuid4().toString(),
                subjectDN = uuid4().toString(),
            ),
        ).apply {
            this.toSigningCredential()
        }
    }

    "certificate without certparameters is invalid" {
        validCert.copy(
            certParameters = dummyValueProvider.getCredentialInfo().certParameters!!.copy(certificates = null)
        ).apply {
            shouldThrow<IllegalArgumentException> { this.toSigningCredential() }
        }
    }

    "CscAuthDetails respects SigningCredential" {
        val digests = dummyValueProvider.buildDocumentDigests()
        val authDetails = rqesWalletService.getCscAuthenticationDetails(
            signingCredential = validCert.toSigningCredential(), digests,
            validSigningAlgo.digest,
            signatureProperties = signatureProperties,
        )
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
            validCert.toSigningCredential().supportedSigningAlgorithms.first(),
            signatureProperties = signatureProperties,
        )
        with(testDocumentDigests) {
            this shouldNotBe null
            this.signAlgoOid shouldBe validSigningAlgo.oid
            // These change before each test
            this.signatureFormat shouldBe signatureProperties.signatureFormat
            this.conformanceLevel shouldBe signatureProperties.conformanceLevel
            this.signedEnvelopeProperty shouldBe signatureProperties.signedEnvelopeProperty
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
            signingCredential = validCert.toSigningCredential(),
            documentDigests = documentDigests,
            redirectUrl = "someOtherURL",
            hashAlgorithm = Digest.entries.random(),
            signatureProperties = signatureProperties,
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
                    signingCredential = validCert.toSigningCredential(),
                    dummyValueProvider.buildDocumentDigests(),
                    Digest.entries.random(),
                    signatureProperties = signatureProperties,
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
            signingCredential = validCert.toSigningCredential(),
            dtbsr = listOf(uuid4().bytes),
            sad = uuid4().toString(),
            signatureAlgorithm = validSigningAlgo,
        ).shouldBeInstanceOf<SignHashRequestParameters>()

        request.credentialId shouldBe validCert.credentialID
        request.signAlgoOid shouldBe validSigningAlgo.oid

        val serialized = vckJsonSerializer.encodeToString(request)
        vckJsonSerializer.decodeFromString<QtspSignatureRequest>(serialized)
            .shouldBe(request)
    }
}

val X509SignatureAlgorithm.digest: Digest
    get() = when (this) {
        is X509SignatureAlgorithm.ECDSA -> digest
        is X509SignatureAlgorithm.RSAPSS -> digest
        is X509SignatureAlgorithm.RSAPKCS1 -> digest
    }