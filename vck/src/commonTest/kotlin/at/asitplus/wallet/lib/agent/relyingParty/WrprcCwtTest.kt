package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
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
        )

        result.exceptionOrNull()?.message.shouldContain(
            "Invalid typ header in euWrprc: expected 'rc-wrp+cwt', got 'not-rc-wrp+cwt'."
        )
    }

    "CWT signature from a non-matching key fails" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprcCose(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        result.exceptionOrNull()?.message.shouldContain(
            "Signature is cryptographically invalid"
        )
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
}
