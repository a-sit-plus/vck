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
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

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
            )
            val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                relyingPartyTrust = setOf(
                    RelyingPartyTrust.VerifierAttesterKeys { setOf(sprsKeyMaterial.jsonWebKey) },
                ),
                randomSource = RandomSource.Default,
            )
            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty().map { it.vcJws }.forEach {
                        it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                            shouldNotThrowAny {
                                AtomicAttribute2023.fromJsonElement(credentialSubject)
                            }
                        }
                    }
                }
        }
        // "test with request object and invalid Attestation JWT" removed: an untrusted attester is covered by
        // OpenId4VpRelyingPartyTrustTest, against the library's own implementation rather than a test-local one.
    }
}


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

