package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OidvciEncryptionTest by testSuite {

    withFixtureGenerator {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(setOf(ConstantIndex.AtomicAttribute2023)),
            )
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true, // this is important
                    decryptionKeyMaterial = EphemeralKeyWithoutCert()
                ),
            )
            val state = uuid4().toString()
            val client = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true, // this is important
                    requireRequestEncryption = true, // this is important
                )
            )
            val oauth2Client = OAuth2Client()
            suspend fun getToken(scope: String): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

        }
    } - {
        test("wallet encrypts credential request and decrypts credential response") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>()
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow().let { credential ->
                    it.client.parseCredentialResponse(credential, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                        .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                            signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                        }
                }
            }
        }

        test("wallet does not encrypt credential request and decrypts credential response") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().forEach { request ->
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow().let { credential ->
                    it.client.parseCredentialResponse(credential, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                        .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                            signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                        }
                }
            }
        }

        test("wallet does not encrypt credential request but issuer requires this") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true,
                    decryptionKeyMaterial = EphemeralKeyWithoutCert(),
                    requireRequestEncryption = true, // this is important for this test
                ),
            )

            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata.copy(credentialRequestEncryption = null), // trick wallet into not encrypting
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().forEach { request ->
                shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                    it.issuer.credential(
                        authorizationHeader = token.toHttpHeaderValue(),
                        params = request,
                        credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    ).getOrThrow()
                }
            }
        }

        test("issuer fails to encrypt response") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true,
                    encryptCredentialResponse = EncryptJweFun { header, payload, recipientKey ->
                        KmmResult.catching { TODO("issuer fails to encrypt") }
                    }
                ),
            )
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().forEach { request ->
                shouldThrowAny {
                    it.issuer.credential(
                        authorizationHeader = token.toHttpHeaderValue(),
                        params = request,
                        credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    ).getOrThrow()
                }
            }
        }
    }

}