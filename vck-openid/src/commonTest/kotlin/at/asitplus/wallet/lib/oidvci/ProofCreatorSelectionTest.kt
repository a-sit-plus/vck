package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs

/**
 * The request carries exactly one proof type, any of the issuer's `proof_types_supported` (OpenID4VCI 1.0, 8.2), and
 * `proofs` "MUST be present" if the issuer lists proof types (8.2), but are not required otherwise (12.2.4).
 */
val ProofCreatorSelectionTest by matrixSuite {

    val metadata = IssuerMetadata(
        credentialIssuer = "https://issuer.example.com",
        credentialEndpointUrl = "https://issuer.example.com/credential",
        supportedCredentialConfigurations = mapOf(),
    )
    val bothProofTypes = SupportedCredentialFormatSdJwt(
        sdJwtVcType = "urn:example:credential",
        supportedProofTypes = mapOf(
            ProofTypes.JWT to CredentialRequestProofSupported(keyAttestationRequired = KeyAttestationRequired()),
            ProofTypes.ATTESTATION to CredentialRequestProofSupported(keyAttestationRequired = KeyAttestationRequired()),
        ),
    )

    suspend fun proofOf(format: SupportedCredentialFormat, vararg creators: ProofCreator) =
        OpenId4VciClient(proofCreators = creators.toList())
            .createCredentialProof(metadata, format, "https://wallet.example.com", "nonce")

    test("the first proof created is used") {
        val proof = CredentialRequestProofContainer()
        val next = FakeProofCreator(KmmResult.success(CredentialRequestProofContainer()))

        proofOf(bothProofTypes, FakeProofCreator(KmmResult.success(proof)), next) shouldBeSameInstanceAs proof
        next.calls shouldBe 0
    }

    test("a creator for another proof type leaves the proof to the next one") {
        val proof = CredentialRequestProofContainer()

        proofOf(
            bothProofTypes,
            FakeProofCreator(KmmResult.success(null)),
            FakeProofCreator(KmmResult.success(proof)),
        ) shouldBeSameInstanceAs proof
    }

    test("a failing creator leaves the proof to the next one") {
        val proof = CredentialRequestProofContainer()

        proofOf(
            bothProofTypes,
            FakeProofCreator(KmmResult.failure(IllegalStateException("no key attestation"))),
            FakeProofCreator(KmmResult.success(proof)),
        ) shouldBeSameInstanceAs proof
    }

    test("a JWT proof without the key attestation the issuer requires leaves the proof to the next creator") {
        val proof = CredentialRequestProofContainer()

        proofOf(
            bothProofTypes,
            JwtProofCreator(EphemeralKeyWithoutCert()),
            FakeProofCreator(KmmResult.success(proof)),
        ) shouldBeSameInstanceAs proof
    }

    test("fails with the first failure, the others suppressed, if no creator creates a proof") {
        val first = IllegalStateException("first")
        val second = IllegalStateException("second")

        shouldThrowAny {
            proofOf(
                bothProofTypes,
                FakeProofCreator(KmmResult.failure(first)),
                FakeProofCreator(KmmResult.success(null)),
                FakeProofCreator(KmmResult.failure(second)),
            )
        }.apply {
            this shouldBeSameInstanceAs first
            suppressedExceptions shouldContainExactly listOf(second)
        }
    }

    test("fails if no creator supports the proof types the issuer lists") {
        shouldThrow<IllegalArgumentException> {
            proofOf(bothProofTypes, FakeProofCreator(KmmResult.success(null)))
        }
    }

    test("sends no proof if the issuer lists no proof types") {
        val creator = FakeProofCreator(KmmResult.success(null))

        proofOf(bothProofTypes.copy(supportedProofTypes = null), creator).shouldBeNull()
        proofOf(bothProofTypes.copy(supportedProofTypes = emptyMap()), creator).shouldBeNull()
    }
}

private class FakeProofCreator(private val result: KmmResult<CredentialRequestProofContainer?>) : ProofCreator {
    var calls = 0
        private set

    override suspend fun invoke(
        credentialIssuer: String,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?,
    ): KmmResult<CredentialRequestProofContainer?> = result.also { calls++ }
}
