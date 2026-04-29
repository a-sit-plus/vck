package at.asitplus.wallet.lib.oidvci

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

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.KeyStorageStatus
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Duration.Companion.days
import kotlin.time.Clock.System

val OidvciAttestationTest by testSuite {
    withFixtureGenerator {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(
                    setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
                ),
            )
            val oauth2Client = OAuth2Client()
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
                proofValidator = ProofValidator(
                    verifyAttestationProof = { true },
                    requireKeyAttestation = true, // this is important, to require key attestation
                )
            )
            val state = uuid4().toString()

            suspend fun getToken(scope: String): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { dummyUser() } }.getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code.shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

            val walletProviderKeyMaterial = EphemeralKeyWithoutCert()
            val clientKeyMaterial = EphemeralKeyWithoutCert()

            var client = WalletService(
                loadKeyAttestation = { input ->
                    catching {
                        SignJwt<KeyAttestationJwt>(walletProviderKeyMaterial, JwsHeaderCertOrJwk())(
                            type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
                            payload = KeyAttestationJwt(
                                issuedAt = System.now(),
                                expiration = System.now() + 1.days,
                                attestedKeys = setOf(clientKeyMaterial.jsonWebKey),
                                nonce = input.clientNonce,
                                keyStorage = setOf("iso_18045_high"),
                                userAuthentication = setOf("iso_18045_high"),
                                certification = "https://example.org/certification/wscd",
                                keyStorageStatus = KeyStorageStatus(
                                    status = buildJsonObject {
                                        putJsonObject("status_list") {
                                            put("idx", 7)
                                            put("uri", "https://example.org/status/key-storage")
                                        }
                                    },
                                    expiration = System.now() + 31.days,
                                ),
                            ),
                            serializer = KeyAttestationJwt.serializer(),
                        ).getOrThrow()
                    }
                },
                keyMaterial = clientKeyMaterial,
            )

        }
    } - {
        test("use key attestation for proof") {
            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
                val credential = it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response

                JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    credential.credentials.shouldNotBeEmpty()
                        .first().credentialString.shouldNotBeNull(),
                    joseCompliantSerializer
                ).getOrThrow()
                    .payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
                    .also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
            }
        }

        test("use key attestation for proof, issuer does not verify it") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
                proofValidator = ProofValidator(
                    verifyAttestationProof = { false }, // do not accept key attestation
                    requireKeyAttestation = true, // this is important, to require key attestation
                )
            )

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
                shouldThrow<OAuth2Exception> {
                    it.issuer.credential(
                        authorizationHeader = token.toHttpHeaderValue(),
                        params = request,
                        credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    ).getOrThrow()
                }
            }
        }

        test("require key attestation for proof, but do not provide one") {
            it.client = WalletService(loadKeyAttestation = null)

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            shouldThrowAny {
                it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce
                ).getOrThrow()
            }
        }

        test("reject key attestation if jwt proof signing key is not attested at index zero") {
            it.client = WalletService(
                loadKeyAttestation = it.client::loadTestKeyAttestation,
                keyMaterial = EphemeralKeyWithoutCert(),
            )

            shouldThrow<IllegalArgumentException> {
                it.client.createCredentialRequestProofJwt(
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    credentialIssuer = it.issuer.metadata.credentialIssuer,
                    keyAttestationRequired = KeyAttestationRequired(),
                )
            }
        }

        test("attestation proof contains the serialized key attestation") {
            val proof = it.client.createCredentialRequestProofAttestation(
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                credentialIssuer = it.issuer.metadata.credentialIssuer,
                keyAttestationRequired = KeyAttestationRequired(),
            )

            proof.attestation.shouldNotBeNull().shouldNotBeEmpty()
            proof.attestationParsed.shouldNotBeNull().first().payload.keyStorageStatus.shouldNotBeNull()
        }

        test("do not require key attestation for proof, so local error shouldn't matter") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
                proofValidator = ProofValidator(
                    verifyAttestationProof = { false }, // do not accept key attestation
                    requireKeyAttestation = false,
                )
            )
            it.client = WalletService(loadKeyAttestation = { catchingUnwrapped { TODO() }.wrap() })

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
                val credential = it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response

                JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    credential.credentials.shouldNotBeEmpty()
                        .first().credentialString.shouldNotBeNull(),
                    joseCompliantSerializer
                ).getOrThrow()
                    .payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
                    .also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
            }
        }

    }
}

private suspend fun WalletService.loadTestKeyAttestation(
    input: WalletService.KeyAttestationInput,
) = catching {
    val walletProviderKeyMaterial = EphemeralKeyWithoutCert()
    val clientKeyMaterial = EphemeralKeyWithoutCert()
    SignJwt<KeyAttestationJwt>(walletProviderKeyMaterial, JwsHeaderCertOrJwk())(
        type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
        payload = KeyAttestationJwt(
            issuedAt = System.now(),
            expiration = System.now() + 1.days,
            attestedKeys = setOf(clientKeyMaterial.jsonWebKey),
            nonce = input.clientNonce,
            keyStorage = setOf("iso_18045_high"),
            userAuthentication = setOf("iso_18045_high"),
            certification = "https://example.org/certification/wscd",
            keyStorageStatus = KeyStorageStatus(
                status = buildJsonObject {
                    putJsonObject("status_list") {
                        put("idx", 7)
                        put("uri", "https://example.org/status/key-storage")
                    }
                },
                expiration = System.now() + 31.days,
            ),
        ),
        serializer = KeyAttestationJwt.serializer(),
    ).getOrThrow()
}

private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
