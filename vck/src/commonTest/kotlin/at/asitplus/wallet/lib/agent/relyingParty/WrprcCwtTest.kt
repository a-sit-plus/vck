package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.DocRequestInfo
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val WrprcCwtTest by matrixSuite {

    "Issuance and validation round-trip" {
        val fixture = buildWrpFixture()

        val result =
            fixture.validateWrprcCose(payload = buildWrpPayload(fixture.wrpIdentifier)).getOrThrow()

        result.certificateValidation.values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidation.toMap().values.all { it.isValid() == true } shouldBe true
    }

    "CWT registration certificate with x5chain in the protected header also validates" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            certificateChainPlacement = CertificateChainPlacement.PROTECTED,
        ).getOrThrow()

        result.certificateValidation.values.all { it?.isValid() == true } shouldBe true
    }

    "Wrong CWT header type fails" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            type = "not-rc-wrp+cwt",
            parsePayload = false,
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validHeader shouldBe false
    }

    "CWT signed under an untrusted CA fails chain validation" {
        val fixture = buildWrpFixture()
        val untrustedSigner = TestCertificateAuthority(name = "Untrusted CA").issue(subjectName = WRPRC_PROVIDER_NAME)

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = untrustedSigner,
        ).getOrThrow()

        val validation = result.certificateValidation.values.single().shouldNotBeNull()
        validation.validChain shouldBe false
        validation.validSignature shouldBe true
    }

    "CWT signature from a non-matching key fails" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validSignature shouldBe false
    }

    "sub not matching the WRPAC identifier fails linkage validation" {
        val fixture = buildWrpFixture(wrpIdentifier = "WRP-${Uuid.generateV4()}")
        val payload = buildWrpPayload(wrpIdentifier = "WRP-${Uuid.generateV4()}")

        val result = fixture.validateWrprcCose(payload = payload).getOrThrow()

        result.certificateValidation.values.all { it?.validLinkage == false }.shouldBe(true)
    }

    "Revoked status list entry fails status validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 0)

        val result = fixture.validateWrprcCose(payload = payload, revokedStatusIndex = 0).getOrThrow()
        result.certificateValidation.values.all { it?.validStatusList == false }.shouldBe(true)
    }

    "Requesting more attributes than the WRPRC declares fails request validation via DocRequest" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDocRequest(claimNames = listOf("given_name", "family_name", "birth_date", "portrait")),
        ).getOrNull().shouldNotBeNull()

        result.certificateValidation.values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidation.toMap().values.single().isValid() shouldBe false
    }

    "CWT WRPRC with unsupported claim values does not authorize a path-only request" {
        val fixture = buildWrpFixture()
        val credential = defaultMdocCredential().copy(
            claim = listOf(WrpClaim(path = listOf(DEFAULT_DOCTYPE, "given_name"), values = listOf("Alice")))
        )

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential)),
            request = mdocDocRequest(claimNames = listOf("given_name")),
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validPayload shouldBe false
    }

    "CWT without a certificate chain has no certificate validation result" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            certificateChainPlacement = CertificateChainPlacement.NONE,
        ).getOrThrow()

        result.certificateValidation.values.single() shouldBe null
    }

    "eUWrprc round-trips as a CBOR byte string" {
        val payload = buildWrpPayload(wrpIdentifier = "WRP-wireformat-test")
        val payloadBytes = coseCompliantSerializer.encodeToByteArray(WrpPayload.serializer(), payload)
        val cose = CoseSigned.create(
            protectedHeader = CoseHeader(type = "rc-wrp+cwt", algorithm = CoseAlgorithm.Signature.RS256),
            unprotectedHeader = null,
            payload = payloadBytes,
            signature = CryptoSignature.RSA(byteArrayOf()),
            payloadSerializer = ByteArraySerializer(),
        )
        val coseBytes = coseCompliantSerializer.encodeToByteArray(cose)

        val docRequestInfo = DocRequestInfo(euWrprc = coseBytes)

        val serialized = coseCompliantSerializer.encodeToByteArray(docRequestInfo)
        val decoded = coseCompliantSerializer.decodeFromByteArray<DocRequestInfo>(serialized)
        decoded shouldBe docRequestInfo

        decoded.euWrprc.shouldNotBeNull() shouldBe coseBytes

        val decodedCose = coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(decoded.euWrprc!!)
        decodedCose shouldBe cose
        decodedCose.payload shouldBe payloadBytes
    }
}
