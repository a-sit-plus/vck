package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedIssuerCertificates
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * A verifier evaluating trust in the credential's issuer during an OpenID4VP flow, i.e. an
 * [OpenId4VpVerifier] with a [VerifierAgent] that has a list of trusted issuer certificates.
 */
val OpenId4VpTrustedIssuerTest by matrixSuite {

    "SD-JWT presented by the holder is verified for a trusted issuer" {
        val ca = TestCertificateAuthority()
        val holder = holderWithSdJwtFrom(ca)

        present(holder, verifierTrusting { setOf(ca.certificate()) })
            .getOrThrow()
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
            .reconstructedJsonObject[CLAIM_GIVEN_NAME].shouldNotBeNull()
    }

    "SD-JWT presented by the holder is not verified for an untrusted issuer" {
        val holder = holderWithSdJwtFrom(TestCertificateAuthority())

        present(holder, verifierTrusting { setOf(TestCertificateAuthority().certificate()) })
            .exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "trust anchor"
    }
}

/** A holder storing an SD-JWT issued by a key with a certificate of [ca]. */
private suspend fun holderWithSdJwtFrom(ca: TestCertificateAuthority): HolderAgent {
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    return HolderAgent(holderKeyMaterial).also {
        issueAndStoreSdJwt(
            it, holderKeyMaterial, IssuerAgent(
                keyMaterial = ca.issue(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
        )
    }
}

private fun verifierTrusting(trustedIssuers: TrustedIssuerCertificates): OpenId4VpVerifier {
    val clientId = "https://example.com/rp/${uuid4()}"
    return OpenId4VpVerifier(
        clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        verifier = VerifierAgent(identifier = clientId, trustedIssuers = trustedIssuers),
    )
}

/** Runs a full OpenID4VP flow, returning the verifier's validation result for the single presented credential. */
private suspend fun present(holder: HolderAgent, verifierOid4vp: OpenId4VpVerifier) =
    verifierOid4vp.createAuthnRequest(
        OpenId4VpRequestOptions(
            presentationRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(
                    credentialScheme = AtomicAttribute2023,
                    representation = SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                )
            ).toDCQLRequest(),
        ),
        CreationOptions.Query("https://example.com/wallet/${uuid4()}")
    ).getOrThrow().url.let { authnRequest ->
        val authnResponse = OpenId4VpHolder(holder = holder, randomSource = RandomSource.Default)
            .createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
            .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
            .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
            .credentialQueryResponseValidations.values
            .shouldBeSingleton().first().shouldBeSingleton().first()
    }
