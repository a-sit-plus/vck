package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.oidc.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class OidvciInteropTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(
                DummyOAuth2DataProvider,
                setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
            ),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
            buildIssuerCredentialDataProviderOverride = ::DummyOAuth2IssuerCredentialDataProvider
        )
    }

    test("Parse EUDIW URL") {
        val url =
            "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Flocalhost%2Fpid-issuer%22%2C%22credential_configuration_ids%22%3A%5B%22eu.europa.ec.eudi.pid_vc_sd_jwt%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22authorization_server%22%3A%22https%3A%2F%2Flocalhost%2Fidp%2Frealms%2Fpid-issuer-realm%22%7D%7D%7D"

        val credentialOffer = WalletService().parseCredentialOffer(url).getOrThrow()
        credentialOffer.grants?.authorizationCode.shouldNotBeNull()
        credentialOffer.credentialIssuer shouldBe "https://localhost/pid-issuer"

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
                "eu.europa.ec.eudi.pid_mso_mdoc": {
                  "format": "mso_mdoc",
                  "scope": "eu.europa.ec.eudi.pid_mso_mdoc",
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ]
                    }
                  },
                  "doctype": "eu.europa.ec.eudi.pid.1",
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
                  "policy": {
                    "one_time_use": true
                  },
                  "claims": {
                    "eu.europa.ec.eudi.pid.1": {
                      "family_name": {
                        "mandatory": true,
                        "display": [
                          {
                            "name": "Current Family Name",
                            "locale": "en"
                          }
                        ]
                      }
                    }
                  }
                },
                "eu.europa.ec.eudi.pid_vc_sd_jwt": {
                  "format": "vc+sd-jwt",
                  "scope": "eu.europa.ec.eudi.pid_vc_sd_jwt",
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
                  "vct": "eu.europa.ec.eudi.pid.1",
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
                    "claims": {
                      "family_name": {
                        "mandatory": false,
                        "display": [
                          {
                            "name": "Current Family Name",
                            "locale": "en"
                          }
                        ]
                      }
                    }
                },
                "org.iso.18013.5.1.mDL": {
                  "format": "mso_mdoc",
                  "scope": "org.iso.18013.5.1.mDL",
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ]
                    }
                  },
                  "doctype": "org.iso.18013.5.1.mDL",
                  "display": [
                    {
                      "name": "Mobile Driving Licence",
                      "locale": "en"
                    }
                  ],
                  "policy": {
                    "one_time_use": false,
                    "batch_size": 2
                  },
                  "claims": {
                    "org.iso.18013.5.1": {
                      "family_name": {
                        "mandatory": true,
                        "display": [
                          {
                            "name": "Last name, surname, or primary identifier of the mDL holder.",
                            "locale": "en"
                          }
                        ]
                      }
                    }
                  }
                }
              }
            }
        """.trimIndent()

        val issuerMetadata = IssuerMetadata.deserialize(credentialIssuerMetadataString).getOrThrow()
        issuerMetadata.credentialIssuer shouldBe "https://localhost/pid-issuer"
        issuerMetadata.authorizationServers!!.shouldHaveSingleElement("https://localhost/idp/realms/pid-issuer-realm")
        issuerMetadata.credentialEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/credentialEndpoint"
        issuerMetadata.deferredCredentialEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/deferredEndpoint"
        issuerMetadata.notificationEndpointUrl shouldBe "https://localhost/pid-issuer/wallet/notificationEndpoint"
        issuerMetadata.credentialResponseEncryption!!.supportedAlgorithms
            .shouldHaveSingleElement(JweAlgorithm.RSA_OAEP_256)
        issuerMetadata.credentialResponseEncryption!!.encryptionRequired shouldBe true

        val credentialConfig = issuerMetadata.supportedCredentialConfigurations!!
            .entries.first { it.key == credentialOffer.configurationIds.first() }.toPair()

        val credential = credentialConfig.second
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        credential.scope shouldBe "eu.europa.ec.eudi.pid_vc_sd_jwt"
        credential.supportedBindingMethods!!.shouldHaveSingleElement("jwk")
        credential.supportedSigningAlgorithms!!.shouldHaveSingleElement("ES256")
        credential.supportedProofTypes!!["jwt"]!!.supportedSigningAlgorithms.shouldContainAll("RS256", "ES256")
        credential.sdJwtVcType shouldBe "eu.europa.ec.eudi.pid.1"
        // this is still wrong in EUDIW's metadata:
        // Should be an array: credentialConfig.credentialDefinition!!.types,
        // but is a single string
    }

    test("process with pre-authorized code, credential offer, and authorization details") {
        val client = WalletService()
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
        val credentialIssuerMetadata = issuer.metadata
        val credentialIdToRequest = credentialOffer.configurationIds.first()
        val state = uuid4().toString()

        val preAuth = credentialOffer.grants?.preAuthorizedCode.shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
            authorizationDetails = client.buildAuthorizationDetails(
                credentialIdToRequest,
                credentialIssuerMetadata.authorizationServers
            )
        )
        val token = authorizationService.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldNotBeNull()
        val first = token.authorizationDetails!!.first().shouldBeInstanceOf<AuthorizationDetails.OpenIdCredential>()
        val credentialRequest = client.createCredentialRequest(
            input = WalletService.CredentialRequestInput.CredentialIdentifier(first.credentialConfigurationId!!),
            clientNonce = token.clientNonce,
            credentialIssuer = credentialIssuerMetadata.credentialIssuer
        ).getOrThrow()

        val credential = issuer.credential(token.accessToken, credentialRequest)
            .getOrThrow()
        credential.credential.shouldNotBeNull()
    }

    test("process with authorization code flow and request options") {
        val client = WalletService()
        val state = uuid4().toString()
        val requestOptions = WalletService.RequestOptions(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        )
        val authorizationDetails = client.buildAuthorizationDetails(requestOptions)
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            authorizationDetails = authorizationDetails,
            resource = issuer.metadata.credentialIssuer
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()

        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            authorizationDetails = authorizationDetails
        )
        val token = authorizationService.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldNotBeNull()
        val credentialRequest = client.createCredentialRequest(
            input = WalletService.CredentialRequestInput.RequestOptions(requestOptions),
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer
        ).getOrThrow()

        val credential = issuer.credential(token.accessToken, credentialRequest)
            .getOrThrow()
        credential.credential.shouldNotBeNull()
    }

    test("process with pre-authorized code, credential offer, and scope") {
        val client = WalletService()
        val credentialOffer = issuer.credentialOfferWithPreAuthnForUser(DummyOAuth2DataProvider.user)
        val credentialIdToRequest = credentialOffer.configurationIds.first()
        // OID4VCI 5.1.2 Using scope Parameter to Request Issuance of a Credential
        val supportedCredentialFormat = issuer.metadata.supportedCredentialConfigurations?.get(credentialIdToRequest)
            .shouldNotBeNull()
        val scope = supportedCredentialFormat.scope
            .shouldNotBeNull()
        val state = uuid4().toString()

        val preAuth = credentialOffer.grants?.preAuthorizedCode
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.PreAuthCode(preAuth.preAuthorizedCode),
            scope = scope,
            resource = issuer.metadata.credentialIssuer,
        )
        val token = authorizationService.token(tokenRequest).getOrThrow()
        token.authorizationDetails.shouldBeNull()

        val credentialRequest = client.createCredentialRequest(
            input = WalletService.CredentialRequestInput.Format(supportedCredentialFormat),
            clientNonce = token.clientNonce,
            credentialIssuer = issuer.metadata.credentialIssuer
        ).getOrThrow()

        val credential = issuer.credential(token.accessToken, credentialRequest)
            .getOrThrow()
        credential.credential.shouldNotBeNull()
    }

})