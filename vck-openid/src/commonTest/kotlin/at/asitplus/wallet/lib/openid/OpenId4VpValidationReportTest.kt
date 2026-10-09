package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.getCredential
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialTrustScope
import at.asitplus.wallet.lib.validation.CredentialTrustScopes
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.ProtocolResponseChecks
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock

val OpenId4VpValidationReportTest by matrixSuite {

    "the report of a response" - {
        listOf(CredentialRepresentation.SD_JWT, CredentialRepresentation.PLAIN_JWT, CredentialRepresentation.ISO_MDOC)
            .asData(nameFn = { "$it" }) - { representation ->

                "accepts a presentation of a trusted issuer with a valid status" {
                    val issuance = trustedIssuance()
                    val result = issuance.present(representation, issuance.verifier(issuance.validator()))

                    result.validationReport.decision shouldBe ACCEPTED
                    result.vpTokenOrThrow().shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                        .presentationValidations.values.shouldBeSingleton().first()
                        .shouldBeSingleton().first().presentation.shouldNotBeNull()
                }

                "rejects a revoked credential, while the legacy result reports it as not fresh" {
                    val issuance = trustedIssuance()
                    val result = issuance.present(representation, issuance.verifier(issuance.validator())) {
                        issuance.revoke(it)
                    }

                    result.validationReport.apply {
                        decision shouldBe REJECTED
                        checks.shouldBeInstanceOf<ProtocolResponseChecks>().apply {
                            requestState shouldBe CheckOutcome.Passed
                            submissionRequirements.shouldBeInstanceOf<CheckOutcome.Failed>()
                        }
                        children.shouldBeSingleton().first().apply {
                            decision shouldBe REJECTED
                            children.shouldBeSingleton().first().checks.shouldBeInstanceOf<CredentialChecks>()
                                .status.mechanisms.shouldBeSingleton().first()
                                .outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
                        }
                    }
                    result.vpTokenResult.isSuccess shouldBe true
                }

                "rejects every presentation by default, without trust anchors" {
                    val issuance = trustedIssuance()
                    val result = issuance.present(representation, issuance.verifier(CredentialValidator()))

                    result.validationReport.decision shouldBe REJECTED
                    result.vpTokenOrThrow().shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                        .presentationValidations.values.flatten().shouldBeSingleton().first().apply {
                            presentation.shouldBeNull()
                            report.children.shouldBeSingleton().first().checks.shouldBeInstanceOf<CredentialChecks>()
                                .issuerTrust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
                        }
                }
            }
    }
}

private suspend fun trustedIssuance(): TrustedIssuance {
    val ca = TestCertificateAuthority()
    val store = InMemoryIssuerCredentialStore()
    val statusListAgent = StatusListAgent(keyMaterial = ca.issue(), issuerCredentialStore = store)
    val issuer = IssuerAgent(
        keyMaterial = ca.issue(),
        issuerCredentialStore = store,
        identifier = "https://issuer.example.com/".toUri(),
        statusListAgent = statusListAgent,
        randomSource = RandomSource.Default,
    )
    return TrustedIssuance(ca, statusListAgent, issuer)
}

/** An issuer and a status list issuer with certificates of one authority, and a holder. */
private class TrustedIssuance(
    val ca: TestCertificateAuthority,
    val statusListAgent: StatusListAgent,
    val issuer: IssuerAgent,
) {
    val holderKey = EphemeralKeyWithoutCert()
    val holder = HolderAgent(holderKey)

    fun validator() = CredentialValidator(
        trustAnchors = CredentialTrustScopes(
            CredentialTrustScope(
                credentialIdentifiers = with(AtomicAttribute2023) { setOf(vcType, sdJwtType, isoDocType) },
                source = "test issuers",
                issuance = { setOf(ca.certificate) },
                status = { setOf(ca.certificate) },
            )
        ),
        statusValidator = StatusValidator(
            StatusListTokenResolver { StatusListJwt(statusListAgent.issueStatusListJwt(), Clock.System.now()) }
        ),
    )

    fun verifier(credentialValidator: CredentialValidator): OpenId4VpVerifier {
        val clientId = "https://example.com/rp/${uuid4()}"
        return OpenId4VpVerifier(
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            credentialValidator = credentialValidator,
        )
    }

    fun revoke(issued: Issuer.IssuedCredential) {
        val status = when (issued) {
            is Issuer.IssuedCredential.VcJwt -> issued.vc.credentialStatus
            is Issuer.IssuedCredential.VcSdJwt -> issued.sdJwtVc.statusElement
            is Issuer.IssuedCredential.Iso -> issued.issuerSigned.issuerAuth.payload?.status
        }
        val index = status.shouldBeInstanceOf<StatusListInfo>().index
        statusListAgent.revokeCredentialByIndex(FixedTimePeriodProvider.timePeriod, index) shouldBe true
    }

    /** Issues a credential to the holder, and runs a full OpenID4VP flow presenting it to [verifier]. */
    suspend fun present(
        representation: CredentialRepresentation,
        verifier: OpenId4VpVerifier,
        afterIssuance: (Issuer.IssuedCredential) -> Unit = {},
    ): AuthnResponseResult.Success {
        val issued = issuer.issueCredential(
            getCredential(holderKey.publicKey, AtomicAttribute2023, representation).getOrThrow()
        ).getOrThrow()
        afterIssuance(issued)
        holder.storeCredential(issued.toStoreCredentialInput()).getOrThrow()
        val authnRequest = verifier.createAuthnRequest(
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = representation,
                        // VC-JWTs are presented as a whole
                        attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                            .takeUnless { representation == CredentialRepresentation.PLAIN_JWT },
                    )
                ).toDCQLRequest(),
            ),
            CreationOptions.Query("https://example.com/wallet/${uuid4()}")
        ).getOrThrow().url
        val authnResponse = OpenId4VpHolder(holder = holder, randomSource = RandomSource.Default)
            .createAuthorizationResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        return verifier.validateAuthnResponse(authnResponse.url).getOrThrow()
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
    }
}
