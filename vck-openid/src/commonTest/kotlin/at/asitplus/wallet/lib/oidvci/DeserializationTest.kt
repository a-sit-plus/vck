package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.vckJsonSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

val DeserializationTest by testSuite {

    test("OID4VCI A.1.1.2. VC Signed as a JWT, Not Using JSON-LD") {
        val input = """
        {
            "credential_issuer": "test",
            "credential_endpoint": "test",
            "credential_configurations_supported": {
                "UniversityDegreeCredential": {
                  "format": "jwt_vc_json",
                  "scope": "UniversityDegree",
                  "cryptographic_binding_methods_supported": [
                    "did:example"
                  ],
                  "credential_signing_alg_values_supported": [
                    "ES256"
                  ],
                  "credential_definition": {
                    "type": [
                      "VerifiableCredential",
                      "UniversityDegreeCredential"
                    ]
                  },
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ]
                    }
                  },
                  "credential_metadata": {
                    "claims": [
                      {
                        "path": ["credentialSubject", "given_name"],
                        "display": [
                          {
                            "name": "Given Name",
                            "locale": "en-US"
                          }
                        ]
                      },
                      {
                        "path": ["credentialSubject", "family_name"],
                        "display": [
                          {
                            "name": "Surname",
                            "locale": "en-US"
                          }
                        ]
                      },
                      {"path": ["credentialSubject", "degree"]},
                      {
                        "path": ["credentialSubject", "gpa"],
                        "mandatory": true,
                        "display": [
                          {
                            "name": "GPA"
                          }
                        ]
                      }
                    ],
                    "display": [
                      {
                        "name": "University Credential",
                        "locale": "en-US",
                        "logo": {
                          "uri": "https://university.example.edu/public/logo.png",
                          "alt_text": "a square logo of a university"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                      }
                    ]
                  }
                }
              }
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<IssuerMetadata>(input).apply {
            supportedCredentialConfigurations.shouldNotBeNull().apply {
                shouldNotBeEmpty()
                get("UniversityDegreeCredential").shouldNotBeNull().apply {
                    format shouldBe CredentialFormatEnum.JWT_VC
                    scope shouldBe "UniversityDegree"
                    supportedBindingMethods.shouldNotBeNull().shouldBeSingleton().shouldContain("did:example")
                    supportedSigningAlgorithms.shouldNotBeNull().apply {
                        shouldContain(SignatureAlgorithm.ECDSAwithSHA256)
                    }
                    supportedProofTypes.shouldNotBeNull().apply {
                        get("jwt").shouldNotBeNull().apply {
                            supportedSigningAlgorithmsParsed.shouldNotBeNull().apply {
                                shouldContain(SignatureAlgorithm.ECDSAwithSHA256)
                            }
                        }
                    }
                    credentialMetadata.shouldNotBeNull().apply {
                        display.shouldNotBeNull().apply {
                            shouldNotBeEmpty()
                            firstOrNull { it.locale == "en-US" }.shouldNotBeNull().apply {
                                name shouldBe "University Credential"
                                logo.shouldNotBeNull().uri shouldBe "https://university.example.edu/public/logo.png"
                                logo.shouldNotBeNull().altText shouldBe "a square logo of a university"
                                backgroundColor shouldBe "#12107c"
                                textColor shouldBe "#FFFFFF"
                            }
                        }
                    }
                }
            }
        }
    }

    test("OID4VCI A.2.2. ISO mDL") {
        val input = """
        {
            "credential_issuer": "test",
            "credential_endpoint": "test",
            "credential_configurations_supported": {
                "org.iso.18013.5.1.mDL": {
                  "format": "mso_mdoc",
                  "doctype": "org.iso.18013.5.1.mDL",
                  "cryptographic_binding_methods_supported": [
                    "cose_key"
                  ],
                  "credential_signing_alg_values_supported": [
                    -7, -9
                  ],
                  "credential_metadata": {
                    "display": [
                      {
                        "name": "Mobile Driving License",
                        "locale": "en-US",
                        "logo": {
                          "uri": "https://state.example.org/public/mdl.png",
                          "alt_text": "state mobile driving license"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                      },
                      {
                        "name": "モバイル運転免許証",
                        "locale": "ja-JP",
                        "logo": {
                          "uri": "https://state.example.org/public/mdl.png",
                          "alt_text": "米国州発行のモバイル運転免許証"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                      }
                    ],
                    "claims": [
                      {
                        "path": ["org.iso.18013.5.1", "given_name"],
                        "display": [
                          {
                            "name": "Given Name",
                            "locale": "en-US"
                          },
                          {
                            "name": "名前",
                            "locale": "ja-JP"
                          }
                        ]
                      },
                      {
                        "path": ["org.iso.18013.5.1", "family_name"],
                        "display": [
                          {
                            "name": "Surname",
                            "locale": "en-US"
                          }
                        ]
                      },
                      {
                        "path": ["org.iso.18013.5.1", "birth_date"],
                        "mandatory": true
                      },
                      {"path": ["org.iso.18013.5.1.aamva", "organ_donor"]}
                    ]
                  }
                }
              }
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<IssuerMetadata>(input).apply {
            supportedCredentialConfigurations.shouldNotBeNull().apply {
                shouldNotBeEmpty()
                get("org.iso.18013.5.1.mDL").shouldNotBeNull().apply {
                    format shouldBe CredentialFormatEnum.MSO_MDOC
                    docType shouldBe "org.iso.18013.5.1.mDL"
                    supportedBindingMethods.shouldNotBeNull().shouldBeSingleton().shouldContain("cose_key")
                    supportedSigningAlgorithms.shouldNotBeNull().apply {
                        shouldContain(SignatureAlgorithm.ECDSAwithSHA256) // both -7 and -9 shall map to this
                    }
                    credentialMetadata.shouldNotBeNull().apply {
                        display.shouldNotBeNull().apply {
                            shouldNotBeEmpty()
                            firstOrNull { it.locale == "en-US" }.shouldNotBeNull().apply {
                                name shouldBe "Mobile Driving License"
                                logo.shouldNotBeNull().uri shouldBe "https://state.example.org/public/mdl.png"
                                logo.shouldNotBeNull().altText shouldBe "state mobile driving license"
                                backgroundColor shouldBe "#12107c"
                                textColor shouldBe "#FFFFFF"
                            }
                        }
                        claimDescription.shouldNotBeNull().apply {
                            shouldNotBeEmpty()
                            firstOrNull { it.path == listOf("org.iso.18013.5.1", "given_name") }.shouldNotBeNull()
                                .also {
                                    it.display.shouldNotBeNull().firstOrNull { it.locale == "en-US" }.shouldNotBeNull()
                                    it.display.shouldNotBeNull().firstOrNull { it.locale == "ja-JP" }.shouldNotBeNull()
                                }
                            firstOrNull { it.path == listOf("org.iso.18013.5.1", "family_name") }.shouldNotBeNull()
                        }
                    }
                }
            }
        }


    }

    test("OID4VCI A.3.2. IETF SD-JWT VC") {
        val input = """
        {
            "credential_issuer": "test",
            "credential_endpoint": "test",
            "credential_configurations_supported": {
                "SD_JWT_VC_example_in_OpenID4VCI": {
                  "format": "dc+sd-jwt",
                  "scope": "SD_JWT_VC_example_in_OpenID4VCI",
                  "cryptographic_binding_methods_supported": [
                    "jwk"
                  ],
                  "credential_signing_alg_values_supported": [
                    "ES256"
                  ],
                  "proof_types_supported": {
                    "jwt": {
                      "proof_signing_alg_values_supported": [
                        "ES256"
                      ],
                      "key_attestations_required": {
                        "key_storage": [ "iso_18045_moderate" ],
                        "user_authentication": [ "iso_18045_moderate" ]
                      }
                    }
                  },
                  "vct": "SD_JWT_VC_example_in_OpenID4VCI",
                  "credential_metadata": {
                    "display": [
                      {
                        "name": "IdentityCredential",
                        "logo": {
                          "uri": "https://university.example.edu/public/logo.png",
                          "alt_text": "a square logo of a university"
                        },
                        "locale": "en-US",
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                      }
                    ],
                    "claims": [
                      {
                        "path": ["given_name"],
                        "display": [
                          {
                            "name": "Given Name",
                            "locale": "en-US"
                          },
                          {
                            "name": "Vorname",
                            "locale": "de-DE"
                          }
                        ]
                      },
                      {
                        "path": ["family_name"],
                        "display": [
                          {
                            "name": "Surname",
                            "locale": "en-US"
                          },
                          {
                            "name": "Nachname",
                            "locale": "de-DE"
                          }
                        ]
                      },
                      {"path": ["email"]},
                      {"path": ["phone_number"]},
                      {
                        "path": ["address"],
                        "display": [
                          {
                            "name": "Place of residence",
                            "locale": "en-US"
                          },
                          {
                            "name": "Wohnsitz",
                            "locale": "de-DE"
                          }
                        ]
                      },
                      {"path": ["address", "street_address"]},
                      {"path": ["address", "locality"]},
                      {"path": ["address", "region"]},
                      {"path": ["address", "country"]},
                      {"path": ["birthdate"]},
                      {"path": ["is_over_18"]},
                      {"path": ["is_over_21"]},
                      {"path": ["is_over_65"]}
                    ]
                  }
                }
              }
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<IssuerMetadata>(input).apply {
            supportedCredentialConfigurations.shouldNotBeNull().apply {
                shouldNotBeEmpty()
                get("SD_JWT_VC_example_in_OpenID4VCI").shouldNotBeNull().apply {
                    format shouldBe CredentialFormatEnum.DC_SD_JWT
                    scope shouldBe "SD_JWT_VC_example_in_OpenID4VCI"
                    sdJwtVcType shouldBe "SD_JWT_VC_example_in_OpenID4VCI"
                    supportedBindingMethods.shouldNotBeNull().shouldBeSingleton().shouldContain("jwk")
                    supportedSigningAlgorithms.shouldNotBeNull().apply {
                        shouldContain(SignatureAlgorithm.ECDSAwithSHA256)
                    }
                    supportedProofTypes.shouldNotBeNull().apply {
                        get("jwt").shouldNotBeNull().apply {
                            supportedSigningAlgorithmsParsed.shouldNotBeNull().apply {
                                shouldContain(SignatureAlgorithm.ECDSAwithSHA256)
                            }
                            keyAttestationRequired.shouldNotBeNull().apply {
                                keyStorage.shouldNotBeNull().shouldContain("iso_18045_moderate")
                                userAuthentication.shouldNotBeNull().shouldContain("iso_18045_moderate")
                            }
                        }
                    }
                    credentialMetadata.shouldNotBeNull().apply {
                        claimDescription.shouldNotBeNull().shouldNotBeEmpty().apply {
                            firstOrNull { it.path == listOf("given_name") }.shouldNotBeNull()
                            firstOrNull { it.path == listOf("family_name") }.shouldNotBeNull()
                            firstOrNull { it.path == listOf("email") }.shouldNotBeNull()
                            firstOrNull { it.path == listOf("phone_number") }.shouldNotBeNull()
                            firstOrNull { it.path == listOf("address") }.shouldNotBeNull()
                            firstOrNull { it.path == listOf("address", "street_address") }.shouldNotBeNull()
                        }
                    }
                }
            }
        }

    }

    test("Idemia Interop Request") {
        val input = """
        {
            "nonce": "iihlPsH0UbzC27dg7zHlli0aVZ/akpDNrafh86kgNRRfcrmL22TR8cZaPyyuFxlOT7U6qGlp400o482nJo7lgg==",
            "state": "b3b2ea02-b959-44e4-a40a-0af2502146d8",
            "iat": 1714722722,
            "exp": 1717314722,
            "nbf": 1714722722,
            "jti": "b3b2ea02-b959-44e4-a40a-0af2502146d8",
            "response_uri": "https://interop.rac-shared.staging.identity-dev.idemia.io/openid4vp/resp/b3b2ea02-b959-44e4-a40a-0af2502146d8",
            "client_id_scheme": "redirect_uri",
            "response_type": "vp_token",
            "client_id": "https://interop.rac-shared.staging.identity-dev.idemia.io/openid4vp/resp/b3b2ea02-b959-44e4-a40a-0af2502146d8",
            "response_mode": "direct_post.jwt",
            "aud": "https://self-issued.me/v2",
            "scope": "openid",
            "presentation_definition": {
            "id": "b3b2ea02-b959-44e4-a40a-0af2502146d8",
            "input_descriptors": [
              {
                "id": "org.iso.18013.5.1.mDL",
                "format": {
                  "mso_mdoc": {
                    "alg": [
                      "ES256"
                    ]
                  }
                },
                "constraints": {
                  "fields": [
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['document_number']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['issue_date']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['issuing_authority']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['birth_date']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['expiry_date']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['given_name']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['portrait']"
                      ],
                      "intent_to_retain": false
                    },
                    {
                      "path": [
                        "${'$'}['org.iso.18013.5.1']['family_name']"
                      ],
                      "intent_to_retain": false
                    }
                  ],
                  "limit_disclosure": "required"
                }
              }
            ]
            },
            "client_metadata": {
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "require_signed_request_object": false,
            "vp_formats": {
              "alg": [
                "ES256"
              ]
            },
            "jwks": {
              "keys": [
                {
                  "kty": "EC",
                  "kid": "ephReaderKey",
                  "use": "enc",
                  "alg": "ECDH-ES",
                  "x": "GSjGTm4gAA-GFhXS1Z3kCREwF7EzlxF9iAsqkGC3ys4",
                  "y": "YQyDOSYyQ3xKFiRWHfUITreUvEo51btt7qw3Apy7F7U",
                  "crv": "P-256"
                }
              ]
            }
            }
            }    
        """.trimIndent()

        vckJsonSerializer.decodeFromString<AuthenticationRequestParameters>(input)
            .shouldNotBeNull()
    }
}