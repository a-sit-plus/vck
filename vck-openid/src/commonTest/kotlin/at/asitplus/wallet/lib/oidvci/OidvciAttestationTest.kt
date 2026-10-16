package at.asitplus.wallet.lib.oidvci

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications:
 * - Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * - Added support for configurable key binding method selection via resolveKeyBindingMethod,
 * allowing the credential request proof JWS header to embed either an inline JsonWebKey (jwk)
 * or a DID URL key identifier (kid), as required by the OID4VCI specification.
 * Exactly one of jwk or kid must be provided; supplying both or neither raises an IllegalArgumentException.
 * The default behaviour (embed jwk inline) is preserved for backward compatibility.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.KeyStorageStatus
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient.KeyAttestationInput
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.JwtProofChecks
import at.asitplus.wallet.lib.validation.KeyAttestationChecks
import at.asitplus.wallet.lib.validation.KeyAttestationValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

val OidvciAttestationTest by matrixSuite {
    fixture {
        object {
            // key attestations are signed with a certificate the wallet provider's anchor issued (EUDI TS3, 2.2.2.2)
            val walletProvider = runBlocking { TestCertificateAuthority() }
            val walletProviderKeyMaterial = runBlocking { walletProvider.issue() }
            val authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            )
            val oauth2Client = OAuth2Client()
            var issuer = OpenId4VciServer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                proofValidator = ProofValidator(
                    requireKeyAttestation = true, // this is important, to require key attestation
                    keyAttestationValidator = trusting(walletProvider),
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
                val authnResponse = authorizationService.authorize(input) {
                    catching {
                        OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
                    }
                }.getOrThrow()
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

            val clientKeyMaterial = EphemeralKeyWithoutCert()

            var client = OpenId4VciClient(
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
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
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
                request.shouldBeInstanceOf<OpenId4VciClient.CredentialRequest.Plain>()
                val credential = it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<OpenId4VciServer.CredentialResponse.Plain>()
                    .response

                JwsCompactTyped<VerifiableCredentialJws>(
                    credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull(),
                ).payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                    shouldNotThrowAny {
                        AtomicAttribute2023.fromJsonElement(credentialSubject)
                    }
                }
            }
        }

        test("reject key attestation in JWT proof, signed by an untrusted key") {
            it.issuer = OpenId4VciServer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                proofValidator = ProofValidator(
                    requireKeyAttestation = true, // this is important, to require key attestation
                    // the client's attestation is signed by walletProviderKeyMaterial, so it must not be accepted
                    keyAttestationValidator = trusting(TestCertificateAuthority()),
                )
            )

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
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
                request.shouldBeInstanceOf<OpenId4VciClient.CredentialRequest.Plain>()
                shouldThrow<OAuth2Exception> {
                    it.issuer.credential(
                        authorizationHeader = token.toHttpHeaderValue(),
                        params = request,
                        credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    ).getOrThrow()
                }.message shouldContain "key attestation not verified"
            }
        }

        test("reject attestation proof signed by an untrusted key") {
            val validator = ProofValidator(keyAttestationValidator = trusting(it.walletProvider))
            val nonce = validator.nonce().clientNonce
            // a rogue wallet provider signs a well-formed attestation, embedding its own key in the JWS header,
            // so the attestation is self-consistent but not issued by the trusted wallet provider
            val rogueAttestation = buildValidKeyAttestation(
                signerKeyMaterial = EphemeralKeyWithoutCert(),
                attestedKey = it.clientKeyMaterial,
                nonce = nonce,
            )

            shouldThrow<OAuth2Exception> {
                validator.validateProofExtractSubjectPublicKeys(
                    CredentialRequestParameters(
                        proofs = CredentialRequestProofContainer(attestation = setOf(rogueAttestation.jws))
                    )
                )
            }.message shouldContain "key attestation not verified"

            // the very same attestation from the trusted wallet provider is accepted, i.e. only the signer differs
            val trustedAttestation = buildValidKeyAttestation(
                signerKeyMaterial = it.walletProviderKeyMaterial,
                attestedKey = it.clientKeyMaterial,
                nonce = nonce,
            )
            validator.validateProofExtractSubjectPublicKeys(
                CredentialRequestParameters(
                    proofs = CredentialRequestProofContainer(attestation = setOf(trustedAttestation.jws))
                )
            ) shouldContainExactly listOf(it.clientKeyMaterial.jsonWebKey.toCryptoPublicKey().getOrThrow())
        }

        test("accept key attestations of any trusted wallet provider with walletProviderAnchors") {
            val trustedAnchor = TestCertificateAuthority()
            val otherTrustedAnchor = TestCertificateAuthority()
            val trustedProvider = trustedAnchor.issue()
            val otherTrustedProvider = otherTrustedAnchor.issue()
            val validator = ProofValidator(
                keyAttestationValidator = KeyAttestationValidator(
                    walletProviderAnchors = { setOf(trustedAnchor.certificate, otherTrustedAnchor.certificate) },
                ),
            )

            listOf(trustedProvider, otherTrustedProvider).forEach { provider ->
                val attestation = buildValidKeyAttestation(
                    signerKeyMaterial = provider,
                    attestedKey = it.clientKeyMaterial,
                    nonce = validator.nonce().clientNonce,
                )
                validator.validateProofExtractSubjectPublicKeys(
                    CredentialRequestParameters(
                        proofs = CredentialRequestProofContainer(attestation = setOf(attestation.jws))
                    )
                ) shouldContainExactly listOf(it.clientKeyMaterial.jsonWebKey.toCryptoPublicKey().getOrThrow())
            }

            val rogueAttestation = buildValidKeyAttestation(
                signerKeyMaterial = EphemeralKeyWithSelfSignedCert(),
                attestedKey = it.clientKeyMaterial,
                nonce = validator.nonce().clientNonce,
            )
            shouldThrow<OAuth2Exception> {
                validator.validateProofExtractSubjectPublicKeys(
                    CredentialRequestParameters(
                        proofs = CredentialRequestProofContainer(attestation = setOf(rogueAttestation.jws))
                    )
                )
            }.message shouldContain "key attestation not verified"
        }

        test("reject key attestation when no trusted verifier is configured") {
            val validator = ProofValidator()
            val attestation = buildValidKeyAttestation(
                signerKeyMaterial = it.walletProviderKeyMaterial,
                attestedKey = it.clientKeyMaterial,
                nonce = validator.nonce().clientNonce,
            )

            shouldThrow<OAuth2Exception> {
                validator.validateProofExtractSubjectPublicKeys(
                    CredentialRequestParameters(
                        proofs = CredentialRequestProofContainer(attestation = setOf(attestation.jws))
                    )
                )
            }.message shouldContain "key attestation not verified"
        }

        test("reject key attestation whose key storage status is revoked") {
            val validator = ProofValidator(
                keyAttestationValidator = trusting(it.walletProvider) { statusListUrl ->
                    buildStatusListToken(statusListUrl, revokedIndex = KEY_STORAGE_STATUS_INDEX)
                },
            )
            val nonce = validator.nonce().clientNonce
            val attestation = buildValidKeyAttestation(
                signerKeyMaterial = it.walletProviderKeyMaterial,
                attestedKey = it.clientKeyMaterial,
                nonce = nonce,
            )

            shouldThrow<OAuth2Exception> {
                validator.validateProofExtractSubjectPublicKeys(
                    CredentialRequestParameters(
                        proofs = CredentialRequestProofContainer(attestation = setOf(attestation.jws))
                    )
                )
            }.message shouldContain "TokenStatus invalid"
        }

        test("accept key attestation whose key storage status is valid") {
            val validator = ProofValidator(
                keyAttestationValidator = trusting(it.walletProvider) { statusListUrl ->
                    // some other key storage is revoked, but not the one of this attestation
                    buildStatusListToken(statusListUrl, revokedIndex = KEY_STORAGE_STATUS_INDEX + 1)
                },
            )
            val nonce = validator.nonce().clientNonce
            val attestation = buildValidKeyAttestation(
                signerKeyMaterial = it.walletProviderKeyMaterial,
                attestedKey = it.clientKeyMaterial,
                nonce = nonce,
            )

            validator.validateProofExtractSubjectPublicKeys(
                CredentialRequestParameters(
                    proofs = CredentialRequestProofContainer(attestation = setOf(attestation.jws))
                )
            ) shouldContainExactly listOf(it.clientKeyMaterial.jsonWebKey.toCryptoPublicKey().getOrThrow())
        }

        test("require key attestation for proof, but do not provide one") {
            it.client = OpenId4VciClient(loadKeyAttestation = null)

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
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
            it.client = OpenId4VciClient(
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

        test("key attestation callback receives issuer preference context") {
            var capturedInput: KeyAttestationInput? = null

            it.client = OpenId4VciClient(
                loadKeyAttestation = { input ->
                    capturedInput = input
                    catching {
                        SignJwt<KeyAttestationJwt>(it.walletProviderKeyMaterial, JwsHeaderCertOrJwk())(
                            type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
                            payload = KeyAttestationJwt(
                                issuedAt = System.now(),
                                expiration = System.now() + 1.days,
                                attestedKeys = setOf(it.clientKeyMaterial.jsonWebKey),
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
                keyMaterial = it.clientKeyMaterial,
                selectProofJwtKeyBinding = { key -> Pair(key.jsonWebKey, null) },
            )

            it.client.createCredentialRequestProofJwt(
                clientNonce = "nonce-123",
                credentialIssuer = "https://issuer.example.com",
                keyAttestationRequired = KeyAttestationRequired(preferredTtl = 5.days),
                supportedAlgorithms = listOf("ES256", "ES384"),
            )

            capturedInput.shouldNotBeNull().also { input ->
                input.credentialIssuer shouldBe "https://issuer.example.com"
                input.clientNonce shouldBe "nonce-123"
                input.supportedAlgorithms.shouldNotBeNull().shouldContainExactly("ES256", "ES384")
                input.preferredKeyStorageStatusPeriod shouldBe 5.days
            }
        }

        test("do not require key attestation for proof, so local error shouldn't matter") {
            it.issuer = OpenId4VciServer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                proofValidator = ProofValidator(
                    requireKeyAttestation = false,
                    keyAttestationValidator = trusting(TestCertificateAuthority()), // not our wallet provider
                )
            )
            it.client = OpenId4VciClient(loadKeyAttestation = { catchingUnwrapped { TODO() }.wrap() })

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
                request.shouldBeInstanceOf<OpenId4VciClient.CredentialRequest.Plain>()
                val credential = it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<OpenId4VciServer.CredentialResponse.Plain>()
                    .response

                JwsCompactTyped<VerifiableCredentialJws>(
                    credential.credentials.shouldNotBeEmpty().first().credentialString.shouldNotBeNull(),
                ).payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                    shouldNotThrowAny {
                        AtomicAttribute2023.fromJsonElement(credentialSubject)
                    }
                }
            }
        }

        test("report of a JWT proof contains the report of its key attestation, and the attested keys") {
            val validator = ProofValidator(keyAttestationValidator = trusting(it.walletProvider))
            val nonce = validator.nonce().clientNonce
            val keyAttestation = buildValidKeyAttestation(it.walletProviderKeyMaterial, it.clientKeyMaterial, nonce)

            validator.validateProofs(it.clientKeyMaterial.jwtProof(nonce, keyAttestation.jws), strictPolicy).apply {
                accepted shouldBe true
                keys shouldContainExactly listOf(it.clientKeyMaterial.jsonWebKey.toCryptoPublicKey().getOrThrow())
                proofs.single().report.apply {
                    checks.shouldBeInstanceOf<JwtProofChecks>()
                    children.single().checks.shouldBeInstanceOf<KeyAttestationChecks>()
                    decision shouldBe ValidationDecision.ACCEPTED
                }
            }
        }

        test("key attestation in a JWT proof needs a server-provided nonce and exp (OpenID4VCI 1.0, F.1, D.1)") {
            val validator = ProofValidator(keyAttestationValidator = trusting(it.walletProvider))
            val nonce = validator.nonce().clientNonce
            val foreignNonce = buildValidKeyAttestation(it.walletProviderKeyMaterial, it.clientKeyMaterial, "foreign")
            val withoutExp = buildValidKeyAttestation(it.walletProviderKeyMaterial, it.clientKeyMaterial, nonce) {
                copy(expiration = null)
            }

            validator.validateProofs(it.clientKeyMaterial.jwtProof(nonce, foreignNonce.jws), strictPolicy)
                .proofs.single().report.children.single().checks.shouldBeInstanceOf<KeyAttestationChecks>()
                .nonce.shouldBeInstanceOf<CheckOutcome.Failed>()
            validator.validateProofs(it.clientKeyMaterial.jwtProof(nonce, withoutExp.jws), strictPolicy)
                .proofs.single().report.children.single().checks.shouldBeInstanceOf<KeyAttestationChecks>()
                .parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        test("a rejected proof does not consume its nonce, and a proof that can not be parsed is reported") {
            val validator = ProofValidator(keyAttestationValidator = trusting(it.walletProvider))
            val nonce = validator.nonce().clientNonce
            val untrusted = buildValidKeyAttestation(EphemeralKeyWithSelfSignedCert(), it.clientKeyMaterial, nonce)
            val trusted = buildValidKeyAttestation(it.walletProviderKeyMaterial, it.clientKeyMaterial, nonce)

            validator.validateProofs(it.clientKeyMaterial.jwtProof(nonce, untrusted.jws), strictPolicy)
                .accepted shouldBe false
            validator.validateProofs(it.clientKeyMaterial.jwtProof(nonce, trusted.jws), strictPolicy)
                .accepted shouldBe true
            // a payload that is no JSON object, i.e. "[]"
            val unparsable = it.clientKeyMaterial.jwtProof(nonce, trusted.jws).proofs!!.jwt!!.single().toString()
                .split(".").let { parts -> JwsCompact("${parts[0]}.W10.${parts[2]}") }
            validator.validateProofs(
                CredentialRequestParameters(proofs = CredentialRequestProofContainer(jwt = setOf(unparsable))),
                strictPolicy,
            ).proofs.single().report.checks.shouldBeInstanceOf<JwtProofChecks>()
                .parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        test("a JWT proof with more than one of kid, jwk and x5c is rejected (OpenID4VCI 1.0, F.1)") {
            val validator = ProofValidator()
            val nonce = validator.nonce().clientNonce
            val holderKey = EphemeralKeyWithSelfSignedCert()
            val proof = SignJwt<JsonWebToken>(holderKey, { header: JwsHeader, key: KeyMaterial ->
                header.copy(jsonWebKey = key.jsonWebKey, certificateChain = listOf(key.getCertificate()!!))
            })(
                OpenIdConstants.PROOF_JWT_TYPE,
                JsonWebToken(audience = PUBLIC_CONTEXT, issuedAt = System.now(), nonce = nonce),
                JsonWebToken.serializer(),
            ).getOrThrow()

            validator.validateProofs(
                CredentialRequestParameters(proofs = CredentialRequestProofContainer(jwt = setOf(proof.jws))),
                strictPolicy,
            ).proofs.single().report.checks.shouldBeInstanceOf<JwtProofChecks>()
                .parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        test("reject key attestation with algorithm not in custom supportedAlgorithms") {
            // ProofValidator restricted to ES256 only; ES384 is in DEFAULT_WALLET_ATTESTATION_ALGORITHMS
            // but must not be accepted here.
            val restrictedValidator = ProofValidator(
                supportedAlgorithms = setOf(JwsAlgorithm.Signature.ES256),
                publicContext = "https://wallet.a-sit.at/credential-issuer",
                keyAttestationValidator = trusting(it.walletProvider),
            )
            val nonce = restrictedValidator.nonce().clientNonce

            val keyAttestation = buildValidKeyAttestation(
                signerKeyMaterial = it.walletProviderKeyMaterial,
                attestedKey = it.clientKeyMaterial,
                nonce = nonce,
            ).jws.withHeaderAlg(JwsAlgorithm.Signature.RS256)

            val jwtProof = SignJwt<JsonWebToken>(
                it.clientKeyMaterial,
                { header: JwsHeader, key: KeyMaterial ->
                    header.copy(jsonWebKey = key.jsonWebKey, keyAttestation = keyAttestation)
                }
            ).invoke(
                OpenIdConstants.PROOF_JWT_TYPE,
                JsonWebToken(
                    audience = "https://wallet.a-sit.at/credential-issuer",
                    issuedAt = System.now(),
                    nonce = nonce,
                ),
                JsonWebToken.serializer(),
            ).getOrThrow()

            val params = CredentialRequestParameters(
                proofs = CredentialRequestProofContainer(jwt = setOf(jwtProof.jws))
            )

            shouldThrow<OAuth2Exception> {
                restrictedValidator.validateProofExtractSubjectPublicKeys(params)
            }.message shouldContain "unsupported key attestation alg"
        }

        test("reject jwt proof with unsupported algorithm") {
            it.issuer = OpenId4VciServer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                proofValidator = ProofValidator(requireKeyAttestation = false)
            )

            val requestOptions = RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().single().shouldBeInstanceOf<OpenId4VciClient.CredentialRequest.Plain>()

            val tamperedProof = request.request.proofs.shouldNotBeNull().jwt.shouldNotBeNull().single()
                .withHeaderAlg(JwsAlgorithm.Signature.RS256)
            val tamperedRequest = request.request.copy(
                proofs = request.request.proofs!!.copy(jwt = setOf(tamperedProof))
            )

            shouldThrow<OAuth2Exception> {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = OpenId4VciClient.CredentialRequest.Plain(tamperedRequest),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        // -----------------------------------------------------------------------------------------
        // selectProofJwtKeyBinding: both jwk and kid set → IllegalArgumentException
        // -----------------------------------------------------------------------------------------
        test("throw when both jwk and kid are set in selectProofJwtKeyBinding") {
            val conflictingClient = OpenId4VciClient(
                keyMaterial = it.clientKeyMaterial,
                loadKeyAttestation = null,
                selectProofJwtKeyBinding = { key ->
                    Pair(key.jsonWebKey, "did:example:123#key-1") // both non-null → conflict
                },
            )

            shouldThrow<IllegalArgumentException> {
                conflictingClient.createCredentialRequestProofJwt(
                    clientNonce = "nonce-abc",
                    credentialIssuer = it.issuer.metadata.credentialIssuer,
                )
            }
        }

        // -----------------------------------------------------------------------------------------
        // selectProofJwtKeyBinding: neither jwk nor kid set → IllegalArgumentException
        // -----------------------------------------------------------------------------------------
        test("throw when neither jwk nor kid is set in selectProofJwtKeyBinding") {
            val emptyBindingClient = OpenId4VciClient(
                keyMaterial = it.clientKeyMaterial,
                loadKeyAttestation = null,
                selectProofJwtKeyBinding = { _ ->
                    Pair(null, null) // neither set → missing binding
                },
            )

            shouldThrow<IllegalArgumentException> {
                emptyBindingClient.createCredentialRequestProofJwt(
                    clientNonce = "nonce-abc",
                    credentialIssuer = it.issuer.metadata.credentialIssuer,
                )
            }
        }

        // -----------------------------------------------------------------------------------------
        // selectProofJwtKeyBinding: kid-only (DID URL) path → proof must be created without error
        // -----------------------------------------------------------------------------------------
        test("create proof using kid (DID URL) key binding method") {
            val didKeyMaterial = it.clientKeyMaterial
            val didUrl = "did:example:holder#key-1"

            val kidOnlyClient = OpenId4VciClient(
                keyMaterial = didKeyMaterial,
                loadKeyAttestation = null,
                selectProofJwtKeyBinding = { _ ->
                    Pair(null, didUrl) // kid only
                },
            )

            // No key attestation required on the issuer side for this sub-test
            it.issuer = OpenId4VciServer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                proofValidator = ProofValidator(requireKeyAttestation = false),
            )

            val proof = shouldNotThrowAny {
                kidOnlyClient.createCredentialRequestProofJwt(
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    credentialIssuer = it.issuer.metadata.credentialIssuer,
                )
            }

            // The resulting JWT set must be non-empty
            proof.jwt.shouldNotBeNull().shouldNotBeEmpty()
        }
    }
}

private suspend fun OpenId4VciClient.loadTestKeyAttestation(
    input: KeyAttestationInput,
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

/** Index of the key storage status of the attestations built here, see [buildValidKeyAttestation]. */
private const val KEY_STORAGE_STATUS_INDEX = 7

/** Status list token for [statusListUrl], with only [revokedIndex] set to [TokenStatus.Invalid]. */
private suspend fun buildStatusListToken(
    statusListUrl: UniformResourceIdentifier,
    revokedIndex: Int,
) = StatusListJwt(
    value = SignJwt<StatusListTokenPayload>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())(
        type = MediaTypes.STATUSLIST_JWT,
        payload = StatusListTokenPayload(
            subject = statusListUrl,
            issuedAt = System.now(),
            revocationList = StatusListView.fromTokenStatuses(
                tokenStatuses = List(revokedIndex + 1) {
                    if (it == revokedIndex) TokenStatus.Invalid else TokenStatus.Valid
                },
                statusBitSize = TokenStatusBitSize.ONE,
            ).toStatusList(DefaultZlibService(), null),
        ),
        serializer = StatusListTokenPayload.serializer(),
    ).getOrThrow(),
    resolvedAt = System.now(),
)

/** Trusts key attestations of [walletProvider], resolving their status with [statusListTokenResolver]. */
private fun trusting(
    walletProvider: TestCertificateAuthority,
    statusListTokenResolver: StatusListTokenResolver? = null,
) = KeyAttestationValidator(
    walletProviderAnchors = { setOf(walletProvider.certificate) },
    statusValidator = StatusValidator(statusListTokenResolver),
)

/** The default `publicContext` of [ProofValidator], i.e. the audience of proofs. */
private const val PUBLIC_CONTEXT = "https://wallet.a-sit.at/credential-issuer"

private val strictPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

/** A `jwt` proof of the credential issuer of [ProofValidator] by default, with the embedded [keyAttestation]. */
private suspend fun KeyMaterial.jwtProof(nonce: String, keyAttestation: JwsCompact) = CredentialRequestParameters(
    proofs = CredentialRequestProofContainer(
        jwt = setOf(
            SignJwt<JsonWebToken>(this, { header: JwsHeader, key: KeyMaterial ->
                header.copy(jsonWebKey = key.jsonWebKey, keyAttestation = keyAttestation)
            })(
                OpenIdConstants.PROOF_JWT_TYPE,
                JsonWebToken(audience = PUBLIC_CONTEXT, issuedAt = System.now(), nonce = nonce),
                JsonWebToken.serializer(),
            ).getOrThrow().jws
        )
    )
)

private suspend fun buildValidKeyAttestation(
    signerKeyMaterial: KeyMaterial,
    attestedKey: KeyMaterial,
    nonce: String,
    alter: KeyAttestationJwt.() -> KeyAttestationJwt = { this },
) = SignJwt<KeyAttestationJwt>(signerKeyMaterial, JwsHeaderCertOrJwk())(
    type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
    payload = KeyAttestationJwt(
        issuedAt = System.now(),
        expiration = System.now() + 1.days,
        attestedKeys = setOf(attestedKey.jsonWebKey),
        nonce = nonce,
        keyStorage = setOf("iso_18045_high"),
        userAuthentication = setOf("iso_18045_high"),
        certification = "https://example.org/certification/wscd",
        keyStorageStatus = KeyStorageStatus(
            status = buildJsonObject {
                putJsonObject("status_list") {
                    put("idx", KEY_STORAGE_STATUS_INDEX)
                    put("uri", "https://example.org/status/key-storage")
                }
            },
            expiration = System.now() + 31.days,
        ),
    ).alter(),
    serializer = KeyAttestationJwt.serializer(),
).getOrThrow()

private suspend fun JwsCompact.withHeaderAlg(alg: JwsAlgorithm.Signature): JwsCompact =
    JwsCompact(jwsHeader.copy(algorithm = alg), plainPayload) { byteArrayOf() }
