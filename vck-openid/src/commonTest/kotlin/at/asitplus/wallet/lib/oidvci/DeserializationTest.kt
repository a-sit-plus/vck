package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class DeserializationTest : FunSpec({

    test("OID4VCI  A.1.1. VC Signed as a JWT, Not Using JSON-LD ") {
        val input = """
        {
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
                    "credential_definition":{
                        "type": [
                            "VerifiableCredential",
                            "UniversityDegreeCredential"
                        ],
                        "credentialSubject": {
                            "given_name": {
                                "display": [
                                    {
                                        "name": "Given Name",
                                        "locale": "en-US"
                                    }
                                ]
                            },
                            "family_name": {
                                "display": [
                                    {
                                        "name": "Surname",
                                        "locale": "en-US"
                                    }
                                ]
                            },
                            "degree": {},
                            "gpa": {
                                "mandatory": true,
                                "display": [
                                    {
                                        "name": "GPA"
                                    }
                                ]
                            }
                        }
                    },
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": [
                                "ES256"
                            ]
                        }
                    },
                    "display": [
                        {
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://university.example.edu/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ]
                }
            }
        }
        """.trimIndent()
        val deserialized = IssuerMetadata.deserialize(input).getOrThrow()

        val credentials = deserialized.supportedCredentialConfigurations.shouldNotBeNull()
        credentials.shouldNotBeEmpty()
        val credential = credentials["UniversityDegreeCredential"].shouldNotBeNull()
        credential.format shouldBe CredentialFormatEnum.JWT_VC
    }

    test("OID4VCI  A.2. ISO mDL ") {
        val input = """
        {
            "credential_configurations_supported": {
                "org.iso.18013.5.1.mDL": {
                    "format": "mso_mdoc",
                    "doctype": "org.iso.18013.5.1.mDL",
                    "cryptographic_binding_methods_supported": [
                        "cose_key"
                    ],
                    "credential_signing_alg_values_supported": [
                        "ES256", "ES384", "ES512"
                    ],
                    "display": [
                        {
                            "name": "Mobile Driving License",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://state.example.org/public/mdl.png",
                                "alt_text": "state mobile driving license"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        },
                        {
                            "name": "モバイル運転免許証",
                            "locale": "ja-JP",
                            "logo": {
                                "url": "https://state.example.org/public/mdl.png",
                                "alt_text": "米国州発行のモバイル運転免許証"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ],
                    "claims": {
                        "org.iso.18013.5.1": {
                            "given_name": {
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
                            "family_name": {
                                "display": [
                                    {
                                        "name": "Surname",
                                        "locale": "en-US"
                                    }
                                ]
                            },
                            "birth_date": {
                                "mandatory": true
                            }
                        },
                        "org.iso.18013.5.1.aamva": {
                            "organ_donor": {}
                        }
                    }
                }
            }
        }
        """.trimIndent()
        val deserialized = IssuerMetadata.deserialize(input).getOrThrow()

        val credentials = deserialized.supportedCredentialConfigurations.shouldNotBeNull()
        credentials.shouldNotBeEmpty()
        val credential = credentials["org.iso.18013.5.1.mDL"].shouldNotBeNull()
        credential.format shouldBe CredentialFormatEnum.MSO_MDOC
        val claims = credential.isoClaims.shouldNotBeNull()
        claims.shouldNotBeEmpty()
        val innerClaims = claims["org.iso.18013.5.1"].shouldNotBeNull()
        innerClaims["given_name"]?.display.shouldNotBeNull()
        innerClaims["family_name"]?.display.shouldNotBeNull()
        innerClaims["birth_date"]?.mandatory?.shouldBeTrue()
        val aamvaClaims = claims["org.iso.18013.5.1.aamva"].shouldNotBeNull()
        aamvaClaims["organ_donor"].shouldNotBeNull()
    }

    test("OID4VCI  A.3. IETF SD-JWT VC") {
        val input = """
        {
            "credential_configurations_supported": {
                "SD_JWT_VC_example_in_OpenID4VCI": {
                    "format": "vc+sd-jwt",
                    "scope": "SD_JWT_VC_example_in_OpenID4VCI",
                    "cryptographic_binding_methods_supported": [
                        "jwk"
                    ],
                    "credential_signing_alg_values_supported": [
                        "ES256"
                    ],
                    "display": [
                        {
                            "name": "IdentityCredential",
                            "locale": "en-US",
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }
                    ],
                    "vct": "SD_JWT_VC_example_in_OpenID4VCI",
                    "claims": {
                        "given_name": {
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
                        "family_name": {
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
                        "email": {},
                        "phone_number": {},
                        "address": {
                            "street_address": {},
                            "locality": {},
                            "region": {},
                            "country": {}
                        },
                        "birthdate": {},
                        "is_over_18": {},
                        "is_over_21": {},
                        "is_over_65": {}
                    }
                }
            }
        }
        """.trimIndent()
        val deserialized = IssuerMetadata.deserialize(input).getOrThrow()

        val credentials = deserialized.supportedCredentialConfigurations.shouldNotBeNull()
        credentials.shouldNotBeEmpty()
        val credential = credentials["SD_JWT_VC_example_in_OpenID4VCI"].shouldNotBeNull()
        credential.format shouldBe CredentialFormatEnum.VC_SD_JWT
        val claims = credential.sdJwtClaims.shouldNotBeNull()
        claims.shouldNotBeEmpty()
        claims["given_name"]?.display.shouldNotBeNull()
        claims["family_name"]?.display.shouldNotBeNull()
        claims["email"].shouldNotBeNull()
        claims["phone_number"].shouldNotBeNull()
        claims["address"].shouldNotBeNull()
        claims["birthdate"].shouldNotBeNull()
        claims["is_over_18"].shouldNotBeNull()
        claims["is_over_21"].shouldNotBeNull()
        claims["is_over_65"].shouldNotBeNull()
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

        val deserialized = AuthenticationRequestParameters.deserialize(input).getOrThrow()
    }

})