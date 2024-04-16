package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyCredentialDataProvider
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

class OidvciInteropTest : FunSpec({

    beforeSpec {
        at.asitplus.wallet.eupid.Initializer.initWithVcLib()
    }

    lateinit var authorizationService: AuthorizationService
    lateinit var issuer: IssuerService

    beforeEach {
        authorizationService = AuthorizationService(
            credentialSchemes = listOf(ConstantIndex.AtomicAttribute2023, ConstantIndex.MobileDrivingLicence2023)
        )
        issuer = IssuerService(
            authorizationService = authorizationService,
            issuer = IssuerAgent.newDefaultInstance(
                cryptoService = DefaultCryptoService(),
                dataProvider = DummyCredentialDataProvider()
            ),
            credentialSchemes = listOf(ConstantIndex.AtomicAttribute2023, ConstantIndex.MobileDrivingLicence2023)
        )
    }

    test("EUDIW URL") {
        val url =
            "eudi-openid4ci://credentialsOffer?credential_offer=%7B%22credential_issuer%22:%22https://localhost/pid-issuer%22,%22credential_configuration_ids%22:[%22eu.europa.ec.eudiw.pid_vc_sd_jwt%22],%22grants%22:%7B%22authorization_code%22:%7B%22authorization_server%22:%22https://localhost/idp/realms/pid-issuer-realm%22%7D%7D%7D"

        val client = WalletService()

        val credentialOffer =
            Url(url).parameters["credential_offer"]?.let { CredentialOffer.deserialize(it).getOrThrow() }
        credentialOffer.shouldNotBeNull()
        println(credentialOffer)
        val credentialIssuerMetadataUrl = credentialOffer.credentialIssuer + PATH_WELL_KNOWN_CREDENTIAL_ISSUER
        val credentialIssuerMetadataString = """
            {
              "credential_issuer": "https://localhost/pid-issuer",
              "authorization_servers": [
                "https://localhost/idp/realms/pid-issuer-realm"
              ],
              "credential_endpoint": "https://localhost/pid-issuer/wallet/credentialEndpoint",
              "deferred_credential_endpoint": "https://localhost/pid-issuer/wallet/deferredEndpoint",
              "notification_endpoint": "https://localhost/pid-issuer/wallet/notificationEndpoint",
              "credential_response_encryption": {
                "alg_values_supported": [
                  "RSA-OAEP-256"
                ],
                "enc_values_supported": [
                  "A128CBC-HS256"
                ],
                "encryption_required": true
              },
              "credential_identifiers_supported": true,
              "credential_configurations_supported": {
                "eu.europa.ec.eudiw.pid_vc_sd_jwt": {
                  "format": "vc+sd-jwt",
                  "scope": "eu.europa.ec.eudiw.pid_vc_sd_jwt",
                  "cryptographic_binding_methods_supported": [
                    "jwk"
                  ],
                  "credential_signing_alg_values_supported": [
                    "ES256"
                  ],
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "RS256",
                        "ES256"
                      ]
                    }
                  },
                  "vct": "eu.europa.ec.eudiw.pid.1",
                  "display": [
                    {
                      "name": "PID",
                      "locale": "en",
                      "logo": {
                        "uri": "https://examplestate.com/public/mdl.png",
                        "alt_text": "A square figure of a PID"
                      }
                    }
                  ],
                  "credential_definition": {
                    "type": ["eu.europa.ec.eudiw.pid.1"],
                    "claims": {
                      "family_name": {
                        "mandatory": false,
                        "display": [
                          {
                            "name": "Current Family Name",
                            "locale": "en"
                          }
                        ]
                      },
                      "issuance_date": {
                        "mandatory": true
                      }
                    }
                  }
                }
              }
            }
        """.trimIndent()

        val credentialIssuerMetadata = IssuerMetadata.deserialize(credentialIssuerMetadataString).getOrThrow()
        credentialIssuerMetadata.credentialIssuer shouldBe "https://localhost/pid-issuer"
        credentialIssuerMetadata.authorizationServers!!.shouldHaveSingleElement("https://localhost/idp/realms/pid-issuer-realm")
        credentialIssuerMetadata.credentialEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/credentialEndpoint"
        credentialIssuerMetadata.deferredCredentialEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/deferredEndpoint"
        credentialIssuerMetadata.notificationEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/notificationEndpoint"
        credentialIssuerMetadata.credentialResponseEncryption!!.supportedAlgorithms.shouldHaveSingleElement("RSA-OAEP-256")
        credentialIssuerMetadata.credentialResponseEncryption!!.supportedEncryptionAlgorithms!!.shouldHaveSingleElement(
            "A128CBC-HS256"
        )
        credentialIssuerMetadata.credentialResponseEncryption!!.encryptionRequired shouldBe true
        credentialIssuerMetadata.supportsCredentialIdentifiers shouldBe true
        // select correct credential config by using a configurationId from the offer it self
        val credentialConfig =
            credentialIssuerMetadata.supportedCredentialConfigurations!![credentialOffer.configurationIds.first()]!!
        credentialConfig.format shouldBe CredentialFormatEnum.VC_SD_JWT
        credentialConfig.scope shouldBe "eu.europa.ec.eudiw.pid_vc_sd_jwt"
        credentialConfig.supportedBindingMethods!!.shouldHaveSingleElement("jwk")
        credentialConfig.supportedSigningAlgorithms!!.shouldHaveSingleElement("ES256")
        credentialConfig.supportedProofTypes!!["jwt"]!!.supportedSigningAlgorithms.shouldContainAll("RS256", "ES256")
        credentialConfig.sdJwtVcType shouldBe "eu.europa.ec.eudiw.pid.1"
        // TODO this is wrong in EUDIW's metadata? Should be an array! credentialConfig.credentialDefinition!!.types
        credentialConfig.credentialDefinition!!.claims!!.firstNotNullOfOrNull { it.key == "family_name" }
            .shouldNotBeNull()

        val authorizationServerMetadataUrl =
            credentialIssuerMetadata.authorizationServers?.firstOrNull()?.plus("/.well-known/openid-configuration")
        // need to get from URL and parse ...
        val authorizationServerMetadata = IssuerMetadata(
            issuer = "https://localhiost/idp/realms/pid-issuer-realm",
            authorizationEndpointUrl = "https://localhost/idp/realms/pid-issuer-realm/protocol/openid-connect/auth"
        )
        val authorizationEndpoint = credentialIssuerMetadata.authorizationEndpointUrl
            ?: authorizationServerMetadata.authorizationEndpointUrl
        authorizationEndpoint.shouldNotBeNull()

        // selection of end-user, which credential to get
        val scopeToRequest = credentialConfig.scope!!
        // would also need to parse from authorizationServerMetadata if `request_parameter_supported` is true and so on ...
        val authnRequest = client.createAuthRequest(scopeToRequest, credentialIssuerMetadata.credentialIssuer)
        println(URLBuilder(authorizationEndpoint)
            .apply {
                authnRequest.encodeToParameters().forEach {
                    this.parameters.append(it.key, it.value)
                }
            }
            .buildString()
        )
        // Clients may also need to push the authorization request, which is a FORM POST 5.1.4

        // TODO Better use https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/blob/main/api_docs/pid_oidc_no_auth.md
        // and maybe need to implement `code_challenge` and so on
    }

    test("process with pre-authorized code and credential offer") {
        val client = WalletService()
        val credentialOffer = issuer.credentialOffer()
        val credentialIssuerMetadata = issuer.metadata
        val credentialConfig =
            credentialIssuerMetadata.supportedCredentialConfigurations!![credentialOffer.configurationIds.first()]!!
        val scopeToRequest = credentialConfig.scope!!
        val authnRequest = client.createAuthRequest(scopeToRequest, credentialIssuerMetadata.credentialIssuer)
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
        code.shouldNotBeNull()
        // TODO Provide a way to authenticate the client ... but how? see `token_endpoint_auth_method` in Client Metadata, RFC 6749
        val tokenRequest = client.createTokenRequestParameters(
            authnResponse.params,
            credentialOffer,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.SD_JWT
            )
        )
        val token = authorizationService.token(tokenRequest).getOrThrow()
        val credentialRequest = client.createCredentialRequestJwt(
            token,
            credentialIssuerMetadata,
            WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.SD_JWT
            )
        ).getOrThrow()
        val credential = issuer.credential(token.accessToken, credentialRequest)

        credential.shouldNotBeNull()
    }
})
