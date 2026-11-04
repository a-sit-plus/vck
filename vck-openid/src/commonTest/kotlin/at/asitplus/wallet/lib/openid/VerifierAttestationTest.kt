package at.asitplus.wallet.lib.openid

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.VerifierAttesters
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement

val VerifierAttestationTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent: Holder = HolderAgent(holderKeyMaterial).also {
                issueAndStorePlainJwt(it, holderKeyMaterial)
            }
            object {
                val holderAgent = holderAgent
                val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
                val clientId: String = "${uuid4()}"
                val redirectUrl: String = "https://example.com/rp/${uuid4()}"
                val walletUrl: String = "https://example.com/wallet/${uuid4()}"
            }
        }
    } - {

        "test with request object and Attestation JWT" {
            val sprsKeyMaterial = EphemeralKeyWithoutCert()
            val attestationJwt = buildAttestationJwt(sprsKeyMaterial, it.clientId, it.verifierKeyMaterial)
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, it.redirectUrl),
                presentationPolicy = testPresentationPolicy,
            )
            val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                relyingPartyValidator = trustingAttester(sprsKeyMaterial),
                randomSource = RandomSource.Default,
            )
            val authnResponse = holderOid4vp.createAuthorizationResponse(authnRequestWithRequestObject).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .singleAcceptedPresentation()
                .shouldBeInstanceOf<ValidatedPresentation.VpJwt>().apply {
                    credentials.shouldNotBeEmpty().map { it.credential }.forEach {
                        it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                            shouldNotThrowAny {
                                AtomicAttribute2023.fromJsonElement(credentialSubject)
                            }
                        }
                    }
                }
        }

        "test with request object and Attestation JWT of an untrusted attester" {
            val attestationJwt = buildAttestationJwt(EphemeralKeyWithoutCert(), it.clientId, it.verifierKeyMaterial)
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.VerifierAttestation(attestationJwt, it.redirectUrl),
            )
            val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url
            val holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                relyingPartyValidator = trustingAttester(EphemeralKeyWithoutCert()),
                randomSource = RandomSource.Default,
            )

            FakeHttpStack(scripted()).execute(
                OpenId4VpProtocolClient(holderOid4vp).prepareAuthorizationResponse(
                    authnRequestWithRequestObject,
                    testPresentationPolicy.copy(trust = TrustPolicy.RequireAuthorizedSigner),
                )
            ).validationReport.decision shouldBe ValidationDecision.REJECTED
        }
    }
}


/** Trusts the verifier attestations signed by [attester]. */
private fun trustingAttester(attester: KeyMaterial) = RelyingPartyValidator(
    trust = RelyingPartyTrustAnchors(verifierAttesters = VerifierAttesters(keys = { setOf(attester.publicKey) }))
)

private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
    presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ).toDCQLRequest(),
)

private suspend fun buildAttestationJwt(
    sprsKeyMaterial: KeyMaterial,
    clientId: String,
    verifierKeyMaterial: KeyMaterial,
): JwsCompactTyped<JsonWebToken> = SignJwt<JsonWebToken>(sprsKeyMaterial, JwsHeaderNone())(
    null,
    JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = clientId,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationClaim = ConfirmationClaim(jsonWebKey = verifierKeyMaterial.jsonWebKey),
    ),
    JsonWebToken.serializer(),
).getOrThrow()

