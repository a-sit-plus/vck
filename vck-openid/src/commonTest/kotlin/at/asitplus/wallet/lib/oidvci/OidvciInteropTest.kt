package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class OidvciInteropTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023, MobileDrivingLicenceScheme)),
            dataProvider = DummyOAuth2DataProvider,
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider
        )
        client = WalletService()
        state = uuid4().toString()
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
        @Suppress("DEPRECATION")
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        credential.scope shouldBe "eu.europa.ec.eudi.pid_vc_sd_jwt"
        credential.supportedBindingMethods!!.shouldHaveSingleElement("jwk")
        credential.supportedSigningAlgorithms!!.shouldHaveSingleElement("ES256")
        credential.supportedProofTypes!!["jwt"]!!.supportedSigningAlgorithms?.shouldContainAll("RS256", "ES256")
        credential.sdJwtVcType shouldBe "eu.europa.ec.eudi.pid.1"
        // this is still wrong in EUDIW's metadata:
        // Should be an array: credentialConfig.credentialDefinition!!.types,
        // but is a single string
    }

    test("parse EUDIW metadata") {
        val input = """
        {
            "issuer": "https://auth.eudiw.dev/realms/pid-issuer-realm",
            "authorization_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/auth",
            "token_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/token",
            "introspection_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/token/introspect",
            "userinfo_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/userinfo",
            "end_session_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/logout",
            "frontchannel_logout_session_supported": true,
            "frontchannel_logout_supported": true,
            "jwks_uri": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/certs",
            "check_session_iframe": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/login-status-iframe.html",
            "grant_types_supported": [
                "authorization_code",
                "implicit",
                "refresh_token",
                "password",
                "client_credentials",
                "urn:openid:params:grant-type:ciba",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
            "acr_values_supported": [
                "0",
                "1"
            ],
            "response_types_supported": [
                "code",
                "none",
                "id_token",
                "token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token"
            ],
            "subject_types_supported": [
                "public",
                "pairwise"
            ],
            "id_token_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "id_token_encryption_alg_values_supported": [
                "RSA-OAEP",
                "RSA-OAEP-256",
                "RSA1_5"
            ],
            "id_token_encryption_enc_values_supported": [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512"
            ],
            "userinfo_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512",
                "none"
            ],
            "userinfo_encryption_alg_values_supported": [
                "RSA-OAEP",
                "RSA-OAEP-256",
                "RSA1_5"
            ],
            "userinfo_encryption_enc_values_supported": [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512"
            ],
            "request_object_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512",
                "none"
            ],
            "request_object_encryption_alg_values_supported": [
                "RSA-OAEP",
                "RSA-OAEP-256",
                "RSA1_5"
            ],
            "request_object_encryption_enc_values_supported": [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512"
            ],
            "response_modes_supported": [
                "query",
                "fragment",
                "form_post",
                "query.jwt",
                "fragment.jwt",
                "form_post.jwt",
                "jwt"
            ],
            "registration_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/clients-registrations/openid-connect",
            "token_endpoint_auth_methods_supported": [
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
                "tls_client_auth",
                "client_secret_jwt"
            ],
            "token_endpoint_auth_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "introspection_endpoint_auth_methods_supported": [
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
                "tls_client_auth",
                "client_secret_jwt"
            ],
            "introspection_endpoint_auth_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "authorization_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "authorization_encryption_alg_values_supported": [
                "RSA-OAEP",
                "RSA-OAEP-256",
                "RSA1_5"
            ],
            "authorization_encryption_enc_values_supported": [
                "A256GCM",
                "A192GCM",
                "A128GCM",
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512"
            ],
            "claims_supported": [
                "aud",
                "sub",
                "iss",
                "auth_time",
                "name",
                "given_name",
                "family_name",
                "preferred_username",
                "email",
                "acr"
            ],
            "claim_types_supported": [
                "normal"
            ],
            "claims_parameter_supported": true,
            "scopes_supported": [
                "openid",
                "offline_access",
                "eu.europa.ec.eudi.pid_vc_sd_jwt",
                "web-origins",
                "eu.europa.ec.eudi.pid_mso_mdoc",
                "roles",
                "org.iso.18013.5.1.mDL"
            ],
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "require_request_uri_registration": true,
            "code_challenge_methods_supported": [
                "plain",
                "S256"
            ],
            "tls_client_certificate_bound_access_tokens": true,
            "dpop_signing_alg_values_supported": [
                "PS384",
                "ES384",
                "RS384",
                "ES256",
                "RS256",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "revocation_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/revoke",
            "revocation_endpoint_auth_methods_supported": [
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post",
                "tls_client_auth",
                "client_secret_jwt"
            ],
            "revocation_endpoint_auth_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "HS256",
                "HS512",
                "ES256",
                "RS256",
                "HS384",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "backchannel_logout_supported": true,
            "backchannel_logout_session_supported": true,
            "device_authorization_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/auth/device",
            "backchannel_token_delivery_modes_supported": [
                "poll",
                "ping"
            ],
            "backchannel_authentication_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/ext/ciba/auth",
            "backchannel_authentication_request_signing_alg_values_supported": [
                "PS384",
                "RS384",
                "EdDSA",
                "ES384",
                "ES256",
                "RS256",
                "ES512",
                "PS256",
                "PS512",
                "RS512"
            ],
            "require_pushed_authorization_requests": false,
            "pushed_authorization_request_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/ext/par/request",
            "mtls_endpoint_aliases": {
                "token_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/token",
                "revocation_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/revoke",
                "introspection_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/token/introspect",
                "device_authorization_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/auth/device",
                "registration_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/clients-registrations/openid-connect",
                "userinfo_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/userinfo",
                "pushed_authorization_request_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/ext/par/request",
                "backchannel_authentication_endpoint": "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/ext/ciba/auth"
            },
            "authorization_response_iss_parameter_supported": true
        }    
        """.trimIndent()

        val parsed = OAuth2AuthorizationServerMetadata.deserialize(input).getOrThrow()

        parsed.issuer shouldBe "https://auth.eudiw.dev/realms/pid-issuer-realm"
        parsed.authorizationEndpoint shouldBe "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/auth"
        parsed.jsonWebKeySetUrl shouldBe "https://auth.eudiw.dev/realms/pid-issuer-realm/protocol/openid-connect/certs"
        parsed.grantTypesSupported.shouldNotBeNull() shouldContainAll listOf("authorization_code")
        parsed.idTokenSigningAlgorithmsSupported.shouldNotBeNull() shouldContain JwsAlgorithm.ES256
        parsed.responseModesSupported.shouldNotBeNull() shouldContainAll listOf(
            "query", "fragment", "form_post", "fragment.jwt", "form_post.jwt", "jwt"
        )
        parsed.scopesSupported.shouldNotBeNull() shouldContainAll listOf(
            "openid", "eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.pid_mso_mdoc", "org.iso.18013.5.1.mDL"
        )
        parsed.dpopSigningAlgValuesSupported.shouldNotBeNull() shouldContain JwsAlgorithm.ES256
    }

})
