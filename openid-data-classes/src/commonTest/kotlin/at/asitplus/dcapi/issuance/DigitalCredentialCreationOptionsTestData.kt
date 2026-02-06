package at.asitplus.dcapi.issuance

val DIGITAL_CREDENTIALS_DEV_JSON = """
{
  "requests": [
    {
      "data": {
        "authorization_server_metadata": {
          "authorization_endpoint": "https://digital-credentials.dev/openid4vci/auth",
          "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
          ],
          "issuer": "https://digital-credentials.dev",
          "response_types_supported": [
            "code",
            "token"
          ],
          "token_endpoint": "https://digital-credentials.dev/openid4vci/token"
        },
        "credential_configuration_ids": [
          "com.emvco.payment_card"
        ],
        "credential_issuer": "https://digital-credentials.dev",
        "credential_issuer_metadata": {
          "batch_credential_issuance": {
            "batch_size": 2
          },
          "credential_configurations_supported": {
            "com.emvco.dpc_sdjwt": {
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk"
              ],
              "format": "dc+sd-jwt",
              "vct": "dpc.cred.card"
            },
            "com.emvco.dpc_v3_2_sdjwt": {
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk"
              ],
              "format": "dc+sd-jwt",
              "vct": "com.emvco.dpc"
            },
            "com.emvco.payment_card": {
              "claims": [
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Holder Name"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "holder_name"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Card Number"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "card_number"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Month of Expiry"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "expiry_month"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Year of Expiry"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "expiry_year"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Card Network"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "card_network"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Card issuer"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "card_issuer"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Payment Account Reference"
                    }
                  ],
                  "path": [
                    "com.emvco.payment_card.1",
                    "par"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Age over 21"
                    }
                  ],
                  "path": [
                    "com.example.1",
                    "age_over_21"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Email Address"
                    }
                  ],
                  "path": [
                    "com.example.1",
                    "email"
                  ]
                }
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "cose_key"
              ],
              "display": [
                {
                  "background_image": {
                    "uri": "data:image/png;base64,..."
                  },
                  "locale": "en-US",
                  "name": "Payment Card"
                }
              ],
              "doctype": "com.emvco.payment_card",
              "format": "mso_mdoc"
            },
            "org.iso.18013.5.1.mDL": {
              "claims": [
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Family Name"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "family_name"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Given Name"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "given_name"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Driving Privs"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "driving_privileges"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Issue Date"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "issue_date"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Expiry Date"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "expiry_date"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Birth Date"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "birth_date"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Document Number"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "document_number"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Issuing Authority"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "issuing_authority"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Issuing Jurisdiction"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "issuing_jurisdiction"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Portrait"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "portrait"
                  ]
                },
                {
                  "display": [
                    {
                      "locale": "en-US",
                      "name": "Age Over 21"
                    }
                  ],
                  "path": [
                    "org.iso.18013.5.1",
                    "age_over_21"
                  ]
                }
              ],
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "cose_key"
              ],
              "display": [
                {
                  "description": "Mobile Driving License",
                  "locale": "en-US",
                  "name": "Driver's License"
                }
              ],
              "doctype": "org.iso.18013.5.1.mDL",
              "format": "mso_mdoc"
            }
          },
          "credential_endpoint": "https://digital-credentials.dev/openid4vci/credential_endpoint",
          "credential_issuer": "https://digital-credentials.dev",
          "nonce_endpoint": "https://digital-credentials.dev/openid4vci/nonce_endpoint"
        },
        "grants": {
          "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlcjIiLCJjcmVkZW50aWFscyI6WyJtZGwxIl19.pfbTkr9eU3HEL_WJoLyri_iVL2Y9iVOpmghvCZaufaw"
          }
        }
      },
      "protocol": "openid4vci1.0"
    }
  ]
}
""".trimIndent()

val WRONG_ISSUER_JSON = """
{
  "requests": [
    {
      "data": {
        "authorization_server_metadata": {
          "authorization_endpoint": "http://localhost:8080/authorize",
          "client_attestation_pop_signing_alg_values_supported": [
            "ES256"
          ],
          "client_attestation_signing_alg_values_supported": [
            "ES256"
          ],
          "dpop_signing_alg_values_supported": [
            "ES256"
          ],
          "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "refresh_token"
          ],
          "introspection_endpoint": "http://localhost:8080/introspect",
          "introspection_endpoint_auth_methods_supported": [
            "attest_jwt_client_auth"
          ],
          "issuer": "http://localhost:8080",
          "pushed_authorization_request_endpoint": "http://localhost:8080/par",
          "request_object_signing_alg_values_supported": [
            "ES256"
          ],
          "require_pushed_authorization_requests": true,
          "token_endpoint": "http://localhost:8080/token",
          "token_endpoint_auth_methods_supported": [
            "attest_jwt_client_auth"
          ],
          "userinfo_endpoint": "http://localhost:8080/userinfo"
        },
        "credential_configuration_ids": [
          "eu.europa.ec.eudi.pid.1",
          "EuPid2023#jwt_vc_json",
          "urn:eudi:pid:1#dc+sd-jwt",
          "org.iso.18013.5.1",
          "urn:eu.europa.ec.eudi:por:1#dc+sd-jwt",
          "eu.europa.ec.eudi.cor.1#dc+sd-jwt",
          "urn:eu.europa.ec.eudi:tax:1#dc+sd-jwt",
          "urn:eudi:ehic:1#dc+sd-jwt",
          "eu.europa.ec.av.1"
        ],
        "credential_issuer": "http://localhost:8080",
        "credential_issuer_metadata": {
          "authorization_servers": [
            "http://localhost:8080"
          ],
          "batch_credential_issuance": {
            "batch_size": 1
          },
          "credential_configurations_supported": {
            "EuPid2023#jwt_vc_json": {
              "credential_definition": {
                "type": [
                  "VerifiableCredential",
                  "EuPid2023"
                ]
              },
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "family_name"
                    ]
                  },
                  {
                    "path": [
                      "given_name"
                    ]
                  },
                  {
                    "path": [
                      "birth_date"
                    ]
                  },
                  {
                    "path": [
                      "family_name_birth"
                    ]
                  },
                  {
                    "path": [
                      "given_name_birth"
                    ]
                  },
                  {
                    "path": [
                      "resident_address"
                    ]
                  },
                  {
                    "path": [
                      "resident_country"
                    ]
                  },
                  {
                    "path": [
                      "resident_state"
                    ]
                  },
                  {
                    "path": [
                      "resident_city"
                    ]
                  },
                  {
                    "path": [
                      "resident_postal_code"
                    ]
                  },
                  {
                    "path": [
                      "resident_street"
                    ]
                  },
                  {
                    "path": [
                      "resident_house_number"
                    ]
                  },
                  {
                    "path": [
                      "sex"
                    ]
                  },
                  {
                    "path": [
                      "nationality"
                    ]
                  },
                  {
                    "path": [
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "issuing_jurisdiction"
                    ]
                  },
                  {
                    "path": [
                      "personal_administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "portrait"
                    ]
                  },
                  {
                    "path": [
                      "email_address"
                    ]
                  },
                  {
                    "path": [
                      "mobile_phone_number"
                    ]
                  },
                  {
                    "path": [
                      "trust_anchor"
                    ]
                  },
                  {
                    "path": [
                      "location_status"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "jwt_vc_json",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "EuPid2023#jwt_vc_json"
            },
            "eu.europa.ec.av.1": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_12"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_13"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_14"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_16"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_18"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_21"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_25"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_60"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_62"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_65"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.av.1",
                      "age_over_68"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                -9
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "cose_key"
              ],
              "doctype": "eu.europa.ec.av.1",
              "format": "mso_mdoc",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "eu.europa.ec.av.1"
            },
            "eu.europa.ec.eudi.cor.1#dc+sd-jwt": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "family_name"
                    ]
                  },
                  {
                    "path": [
                      "given_name"
                    ]
                  },
                  {
                    "path": [
                      "birth_date"
                    ]
                  },
                  {
                    "path": [
                      "residence_address"
                    ]
                  },
                  {
                    "path": [
                      "gender"
                    ]
                  },
                  {
                    "path": [
                      "birth_place"
                    ]
                  },
                  {
                    "path": [
                      "arrival_date"
                    ]
                  },
                  {
                    "path": [
                      "nationality"
                    ]
                  },
                  {
                    "path": [
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "issuing_jurisdiction"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "dc+sd-jwt",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "eu.europa.ec.eudi.cor.1#dc+sd-jwt",
              "vct": "eu.europa.ec.eudi.cor.1"
            },
            "eu.europa.ec.eudi.pid.1": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "family_name"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "given_name"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "birth_date"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "family_name_birth"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "given_name_birth"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_address"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_country"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_state"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_city"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_postal_code"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_street"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "resident_house_number"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "sex"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "nationality"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "issuing_jurisdiction"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "personal_administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "portrait"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "email_address"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "mobile_phone_number"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "trust_anchor"
                    ]
                  },
                  {
                    "path": [
                      "eu.europa.ec.eudi.pid.1",
                      "location_status"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                -9
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "cose_key"
              ],
              "doctype": "eu.europa.ec.eudi.pid.1",
              "format": "mso_mdoc",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "eu.europa.ec.eudi.pid.1"
            },
            "org.iso.18013.5.1": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "family_name"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "given_name"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "birth_date"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "issue_date"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "portrait"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "driving_privileges"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "un_distinguishing_sign"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "sex"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "height"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "weight"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "eye_colour"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "hair_colour"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "birth_place"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "resident_address"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "portrait_capture_date"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_in_years"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_birth_year"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_12"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_13"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_14"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_16"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_18"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_21"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_25"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_60"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_62"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_65"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "age_over_68"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "issuing_jurisdiction"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "nationality"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "resident_city"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "resident_state"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "resident_postal_code"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "resident_country"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "family_name_national_character"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "given_name_national_character"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "signature_usual_mark"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "biometric_template_face"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "biometric_template_finger"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "biometric_template_signature_sign"
                    ]
                  },
                  {
                    "path": [
                      "org.iso.18013.5.1",
                      "biometric_template_iris"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                -9
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "cose_key"
              ],
              "doctype": "org.iso.18013.5.1.mDL",
              "format": "mso_mdoc",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "org.iso.18013.5.1"
            },
            "urn:eu.europa.ec.eudi:por:1#dc+sd-jwt": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "legal_person_identifier"
                    ]
                  },
                  {
                    "path": [
                      "legal_name"
                    ]
                  },
                  {
                    "path": [
                      "full_powers"
                    ]
                  },
                  {
                    "path": [
                      "eService"
                    ]
                  },
                  {
                    "path": [
                      "effective_from_date"
                    ]
                  },
                  {
                    "path": [
                      "effective_until_date"
                    ]
                  },
                  {
                    "path": [
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "issuing_jurisdiction"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "dc+sd-jwt",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "urn:eu.europa.ec.eudi:por:1#dc+sd-jwt",
              "vct": "urn:eu.europa.ec.eudi:por:1"
            },
            "urn:eu.europa.ec.eudi:tax:1#dc+sd-jwt": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "tax_number"
                    ]
                  },
                  {
                    "path": [
                      "affiliation_country"
                    ]
                  },
                  {
                    "path": [
                      "registered_family_name"
                    ]
                  },
                  {
                    "path": [
                      "registered_given_name"
                    ]
                  },
                  {
                    "path": [
                      "resident_address"
                    ]
                  },
                  {
                    "path": [
                      "birth_date"
                    ]
                  },
                  {
                    "path": [
                      "church_tax_ID"
                    ]
                  },
                  {
                    "path": [
                      "iban"
                    ]
                  },
                  {
                    "path": [
                      "pid_id"
                    ]
                  },
                  {
                    "path": [
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "verification_status"
                    ]
                  },
                  {
                    "path": [
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "issuing_jurisdiction"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "dc+sd-jwt",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "urn:eu.europa.ec.eudi:tax:1#dc+sd-jwt",
              "vct": "urn:eu.europa.ec.eudi:tax:1"
            },
            "urn:eudi:ehic:1#dc+sd-jwt": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "social_security_number"
                    ]
                  },
                  {
                    "path": [
                      "personal_administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority",
                      "id"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority",
                      "name"
                    ]
                  },
                  {
                    "path": [
                      "authentic_source"
                    ]
                  },
                  {
                    "path": [
                      "authentic_source",
                      "id"
                    ]
                  },
                  {
                    "path": [
                      "authentic_source",
                      "name"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "issuance_date"
                    ]
                  },
                  {
                    "path": [
                      "date_of_issuance"
                    ]
                  },
                  {
                    "path": [
                      "expiry_date"
                    ]
                  },
                  {
                    "path": [
                      "date_of_expiry"
                    ]
                  },
                  {
                    "path": [
                      "starting_date"
                    ]
                  },
                  {
                    "path": [
                      "ending_date"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "dc+sd-jwt",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "urn:eudi:ehic:1#dc+sd-jwt",
              "vct": "urn:eudi:ehic:1"
            },
            "urn:eudi:pid:1#dc+sd-jwt": {
              "credential_metadata": {
                "claims": [
                  {
                    "path": [
                      "family_name"
                    ]
                  },
                  {
                    "path": [
                      "given_name"
                    ]
                  },
                  {
                    "path": [
                      "birthdate"
                    ]
                  },
                  {
                    "path": [
                      "place_of_birth",
                      "country"
                    ]
                  },
                  {
                    "path": [
                      "place_of_birth",
                      "region"
                    ]
                  },
                  {
                    "path": [
                      "place_of_birth",
                      "locality"
                    ]
                  },
                  {
                    "path": [
                      "nationalities"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "formatted"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "country"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "region"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "locality"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "postal_code"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "street_address"
                    ]
                  },
                  {
                    "path": [
                      "address",
                      "house_number"
                    ]
                  },
                  {
                    "path": [
                      "birth_family_name"
                    ]
                  },
                  {
                    "path": [
                      "birth_given_name"
                    ]
                  },
                  {
                    "path": [
                      "email"
                    ]
                  },
                  {
                    "path": [
                      "phone_number"
                    ]
                  },
                  {
                    "path": [
                      "picture"
                    ]
                  },
                  {
                    "path": [
                      "date_of_expiry"
                    ]
                  },
                  {
                    "path": [
                      "date_of_issuance"
                    ]
                  },
                  {
                    "path": [
                      "personal_administrative_number"
                    ]
                  },
                  {
                    "path": [
                      "sex"
                    ]
                  },
                  {
                    "path": [
                      "issuing_authority"
                    ]
                  },
                  {
                    "path": [
                      "issuing_country"
                    ]
                  },
                  {
                    "path": [
                      "document_number"
                    ]
                  },
                  {
                    "path": [
                      "issuing_jurisdiction"
                    ]
                  },
                  {
                    "path": [
                      "trust_anchor"
                    ]
                  }
                ]
              },
              "credential_signing_alg_values_supported": [
                "ES256"
              ],
              "cryptographic_binding_methods_supported": [
                "jwk",
                "urn:ietf:params:oauth:jwk-thumbprint"
              ],
              "format": "dc+sd-jwt",
              "proof_types_supported": {
                "jwt": {
                  "proof_signing_alg_values_supported": [
                    "ES256"
                  ]
                }
              },
              "scope": "urn:eudi:pid:1#dc+sd-jwt",
              "vct": "urn:eudi:pid:1"
            }
          },
          "credential_endpoint": "http://localhost:8080/credential",
          "credential_issuer": "http://localhost:8080",
          "issuer": "http://localhost:8080",
          "nonce_endpoint": "http://localhost:8080/nonce"
        },
        "grants": {
          "authorization_code": {
            "authorization_server": "http://localhost:8080",
            "issuer_state": "8a859e8b-7912-4216-b585-0ca80c69c8d4"
          }
        }
      },
      "protocol": "openid4vci-v1"
    }
  ]
}
""".trimIndent()
