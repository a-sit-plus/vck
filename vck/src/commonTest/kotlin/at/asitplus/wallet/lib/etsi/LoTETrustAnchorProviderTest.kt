package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

object LoTETestData {
    val pidProvidersPayload = """
      {
        "ListAndSchemeInformation": {
          "LoTEVersionIdentifier": 1,
          "LoTESequenceNumber": 9,
          "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
          "SchemeOperatorName": [
            {
              "lang": "en",
              "value": "European Commission"
            },
            {
              "lang": "bg",
              "value": "Европейска комисия"
            },
            {
              "lang": "es",
              "value": "Comisión Europea"
            },
            {
              "lang": "cs",
              "value": "Evropská komise"
            },
            {
              "lang": "da",
              "value": "Europa-Kommissionen"
            },
            {
              "lang": "de",
              "value": "Europäische Kommission"
            },
            {
              "lang": "et",
              "value": "Euroopa Komisjon"
            },
            {
              "lang": "el",
              "value": "Ευρωπαϊκή Επιτροπή"
            },
            {
              "lang": "fr",
              "value": "Commission européenne"
            },
            {
              "lang": "it",
              "value": "Commissione europea"
            },
            {
              "lang": "lv",
              "value": "Eiropas Komisija"
            },
            {
              "lang": "lt",
              "value": "Europos Komisija"
            },
            {
              "lang": "hu",
              "value": "Európai Bizottság"
            },
            {
              "lang": "mt",
              "value": "Il-Kummissjoni Ewropea"
            },
            {
              "lang": "nl",
              "value": "Europese Commissie"
            },
            {
              "lang": "pl",
              "value": "Komisja Europejska"
            },
            {
              "lang": "pt",
              "value": "Comissão Europeia"
            },
            {
              "lang": "ro",
              "value": "Comisia Europeană"
            },
            {
              "lang": "sk",
              "value": "Európska komisia"
            },
            {
              "lang": "sl",
              "value": "Evropska komisija"
            },
            {
              "lang": "fi",
              "value": "Euroopan komissio"
            },
            {
              "lang": "sv",
              "value": "Europeiska kommissionen"
            },
            {
              "lang": "hr",
              "value": "Europska komisija"
            }
          ],
          "SchemeOperatorAddress": {
            "SchemeOperatorPostalAddress": [
              {
                "lang": "fr",
                "StreetAddress": "Rue de la Loi 200",
                "Locality": "Bruxelles",
                "PostalCode": "1049",
                "Country": "BE"
              },
              {
                "lang": "nl",
                "StreetAddress": "Wetstraat 200",
                "Locality": "Brussel",
                "PostalCode": "1049",
                "Country": "BE"
              },
              {
                "lang": "en",
                "StreetAddress": "Rue de la Loi/Wetstraat 200",
                "Locality": "Brussels",
                "PostalCode": "1049",
                "Country": "BE"
              }
            ],
            "SchemeOperatorElectronicAddress": [
              {
                "lang": "en",
                "uriValue": "mailto:DIGIT-EU-TRUST-NON-PROD@ec.europa.eu"
              },
              {
                "lang": "en",
                "uriValue": "https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists"
              }
            ]
          },
          "SchemeName": [
            {
              "lang": "en",
              "value": "The present list is a list of person identifier providers of EUDI Wallet issued in accordance with CIR 2024/2980"
            }
          ],
          "SchemeInformationURI": [
            {
              "lang": "en",
              "uriValue": "https://trust.tech.ec.europa.eu/lists/eudiw/pid-providers-list-scheme-information"
            }
          ],
          "StatusDeterminationApproach": "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
          "SchemeTypeCommunityRules": [
            {
              "lang": "en",
              "uriValue": "http://uri.etsi.org/19602/PIDProviders/schemerules/EU"
            }
          ],
          "SchemeTerritory": "EU",
          "PolicyOrLegalNotice": [
            {
              "LoTEPolicy": {
                "lang": "en",
                "uriValue": "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"
              }
            }
          ],
          "ListIssueDateTime": "2026-08-13T16:59:16Z",
          "NextUpdate": "2027-02-12T16:59:16Z"
        },
        "TrustedEntitiesList": [
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Digitaliseringsdirektoratet - Bevisporten"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "NTRNO-NOFOR.991825827"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "5788",
                    "Country": "NO"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.no"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+4734869323"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test.no"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/NO"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_PID_solution_no"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDBTCCAqygAwIBAgIJALyA/nuVMsUpMAoGCCqGSM49BAMEMIGCMR4wHAYDVQRhExVOVFJOTy1OT0ZPUi45OTE4MjU4MjcxLTArBgNVBAMTJGVpZGFzMnNhbmRrYXNzZSBFQUEgUHJvdmlkZXIgQ0EgdGVzdDEkMCIGA1UEChMbRElHSVRBTElTRVJJTkdTRElSRUtUT1JBVEVUMQswCQYDVQQGEwJOTzAeFw0yNTEwMTAwODE2MzZaFw0yNjEwMDgxMjQ3MzZaMGExCzAJBgNVBAYTAk5PMTIwMAYDVQQDDClEaWdpdGFsaXNlcmluZ3NkaXJla3RvcmF0ZXQgLSBCZXZpc3BvcnRlbjEeMBwGA1UEYQwVTlRSTk8tTk9GT1IuOTkxODI1ODI3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEggybfUUfbzJltJnTd3NjkH/OApRXdjznhsiDEShxa14362U8s1d/z8fsFMNxiO+z/ZSkHsUurkh2EiNQMcG0T6OCASkwggElMB8GA1UdIwQYMBaAFG2uFOu+dBM1aEzXwQ1nMTFpj7JfMB0GA1UdDgQWBBRTpQH9HAw203fM8Z6Nnc6Aj5RsVzAMBgNVHRMBAf8EAjAAMFwGA1UdHwRVMFMwUaBPoE2GS2h0dHBzOi8vY2EudGVzdC5laWRhczJzYW5ka2Fzc2UubmV0L3YxL2NlcnRzL2ludGVybWVkaWF0ZXMvZWFhX3Byb3ZpZGVyLmNybDBnBggrBgEFBQcBAQRbMFkwVwYIKwYBBQUHMAKGS2h0dHBzOi8vY2EudGVzdC5laWRhczJzYW5ka2Fzc2UubmV0L3YxL2NlcnRzL2ludGVybWVkaWF0ZXMvZWFhX3Byb3ZpZGVyLmNlcjAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwQDRwAwRAIgco5xnaAZPzLFF0aC7FbF3bEmbHsXId42CRiZIJdqyK0CIG9cjXM31kTF3kmHgN8NligxMbxEmT2HjkAYkKRKUUZR"
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Digitaliseringsdirektoratet - PID-utsteder"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "NTRNO-NOFOR.991825827"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "3478",
                    "Country": "NO"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.no"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+47348346754"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test.no"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/NO"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_PID_solution_no_2"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDMzCCAtmgAwIBAgIIGkwIqxyvEDswCgYIKoZIzj0EAwQwZzEYMBYGA1UEYRMPTlRSTk8tOTkxODI1ODI3MQswCQYDVQQGEwJubzEPMA0GA1UECxMGRGlnZGlyMS0wKwYDVQQDEyRlaWRhczJzYW5ka2Fzc2UgUElEIFByb3ZpZGVyIENBIHRlc3QwHhcNMjUxMDE1MTExMzA3WhcNMjYxMDE1MTExMzA3WjBiMQswCQYDVQQGEwJOTzEzMDEGA1UEAwwqRGlnaXRhbGlzZXJpbmdzZGlyZWt0b3JhdGV0IC0gUElELXV0c3RlZGVyMR4wHAYDVQRhDBVOVFJOTy1OT0ZPUi45OTE4MjU4MjcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATLIEmdVcdTVfQ/6YpsPvS4taSRiebXwcjHWGEWpZLfrKb3yvowmUMe2SaDZD8HCOXjvSXfbIQsgFKeMU88IkNaDOfyMHbXYf3cJZCFJYo799hQL6j2tMogjUMkyoP+dnCjggFVMIIBUTAfBgNVHSMEGDAWgBRX7XviJqjDMVi/g0bAr0FvQshSDDAdBgNVHQ4EFgQUUCIS5a/pLXMjHV+a4AV8NkiRHZMwDAYDVR0TAQH/BAIwADBcBgNVHR8EVTBTMFGgT6BNhktodHRwczovL2NhLnRlc3QuZWlkYXMyc2FuZGthc3NlLm5ldC92MS9jZXJ0cy9pbnRlcm1lZGlhdGVzL3BpZF9wcm92aWRlci5jcmwwZwYIKwYBBQUHAQEEWzBZMFcGCCsGAQUFBzAChktodHRwczovL2NhLnRlc3QuZWlkYXMyc2FuZGthc3NlLm5ldC92MS9jZXJ0cy9pbnRlcm1lZGlhdGVzL3BpZF9wcm92aWRlci5jZXIwDgYDVR0PAQH/BAQDAgWgMCoGCCsGAQUFBwEDAQH/BBswGQYGBACORgEGDA9pZC1ldHNpLXFjdC1waWQwCgYIKoZIzj0EAwQDSAAwRQIgPNu17SJ+E628cVBT1J1CCZQEI85MIG1hqm1ynwyQN84CIQC67g+mvEDLF9C5gcwN8Q38IEJu3bw0EhCvBbUqPORQPA=="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Digi- ja väestötietovirasto"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATFI-8567"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "5685",
                    "Country": "FI"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.fi"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+358348346754"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test.fi"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/FI"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_PID_solution_fi"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDDTCCApKgAwIBAgIUaqDAxDTFQMkDVdM0LpPFNCskEV4wCgYIKoZIzj0EAwMwgagxODA2BgNVBAMML0RWViBEaWdpLUlEIE1vY2sgQXR0cmlidXRlIFNlYWxpbmcgQ2VydGlmaWNhdGVzMSYwJAYDVQQKDB1EaWdpLSBqYSB2w6Rlc3TDtnRpZXRvdmlyYXN0bzERMA8GA1UEBwwISGVsc2lua2kxCzAJBgNVBAYTAkZJMRAwDgYDVQQIDAdGaW5sYW5kMRIwEAYDVQQFEwkwMjQ1NDM3LTIwHhcNMjQwMTE1MDkyNTE5WhcNMzMwMTEyMDkyNTE5WjCBqDE4MDYGA1UEAwwvRFZWIERpZ2ktSUQgTW9jayBBdHRyaWJ1dGUgU2VhbGluZyBDZXJ0aWZpY2F0ZXMxJjAkBgNVBAoMHURpZ2ktIGphIHbDpGVzdMO2dGlldG92aXJhc3RvMREwDwYDVQQHDAhIZWxzaW5raTELMAkGA1UEBhMCRkkxEDAOBgNVBAgMB0ZpbmxhbmQxEjAQBgNVBAUTCTAyNDU0MzctMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABGcz86+Pt3o1TZ5BYKXtOrFhqi6fDVq7+32J8DaeiSibJES5c9mAPIP/eNB8b+Wm+7RU9blUZ3xlxsmVTGScEOwwSVczmiwBHtk4+7KNltd6CrAAFgSdyDKCEe+w+AKwLqN7MHkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwGQYDVR0SBBIwEIYOaHR0cHM6Ly9kdnYuZmkwGQYDVR0RBBIwEIYOaHR0cHM6Ly9kdnYuZmkwHQYDVR0OBBYEFJNVLFsDRkyYNcoRYUEBvtvpEOv7MAoGCCqGSM49BAMDA2kAMGYCMQCwfwzQ2A07a3RiA3BUs2BhdNNuhiZcj5HZN7H8fEEiSvkHay67c2XvuyRlZ+zhE18CMQD6OMM6GM+7oKSBtHEbXuiskiWhl9nq7FPQDwPFoaVGxu/SQ3itFL4k2nNsJrEBcfg="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "eidas2sandkasse PID Provider CA test"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "NTRNO-991825827"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "9678",
                    "Country": "NO"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.no"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+47348346754"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test.no"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/NO"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_PID_solution_no_3"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICvTCCAmSgAwIBAgIJAJ7Fdm0r3xiMMAoGCCqGSM49BAMDMGMxGDAWBgNVBGETD05UUk5PLTk5MTgyNTgyNzELMAkGA1UEBhMCbm8xDzANBgNVBAsTBkRpZ2RpcjEpMCcGA1UEAxMgZWlkYXMyc2FuZGthc3NlLm5ldCByb290IENBIHRlc3QwHhcNMjUwNzE0MDk1MDE5WhcNMjkxMjE2MDk1MDE5WjBnMRgwFgYDVQRhEw9OVFJOTy05OTE4MjU4MjcxCzAJBgNVBAYTAm5vMQ8wDQYDVQQLEwZEaWdkaXIxLTArBgNVBAMTJGVpZGFzMnNhbmRrYXNzZSBQSUQgUHJvdmlkZXIgQ0EgdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMyVKdaQbLy6E4y7A2Crz/7qBv2x9vebD+7B3N0o2rpxXsDzOQYkBBaBh8uD2LxmEI3E3a6vISekCY0NK/nhUR2jgfwwgfkwUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwczovL2NhLnRlc3QuZWlkYXMyc2FuZGthc3NlLm5ldC92MS9jZXJ0cy9yb290LmNlcjAdBgNVHQ4EFgQUV+174iaowzFYv4NGwK9Bb0LIUgwwDgYDVR0PAQH/BAQDAgEGMAwGA1UdEwQFMAMBAf8wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9jYS50ZXN0LmVpZGFzMnNhbmRrYXNzZS5uZXQvdjEvY2VydHMvcm9vdC5jcmwwHwYDVR0jBBgwFoAUCi/G/x9Z1uJAVlFqD3onNXclrPEwCgYIKoZIzj0EAwMDRwAwRAIgLvJLEoUbacsoa2calE0f/XVOAnHDWVYDizHJqJAwS3kCIDz8miu6b8cD09rfGSD727joqPunkIGRQqi72HTVabcA"
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "eidas2sandkasse Pub EAA Provider CA test"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "NTRNO-991825827"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "5784",
                    "Country": "NO"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.no"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+4734869323"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test.no"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/NO"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_PID_solution_no_4"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICwjCCAmigAwIBAgIJAPm2yYm712+4MAoGCCqGSM49BAMDMGMxGDAWBgNVBGETD05UUk5PLTk5MTgyNTgyNzELMAkGA1UEBhMCbm8xDzANBgNVBAsTBkRpZ2RpcjEpMCcGA1UEAxMgZWlkYXMyc2FuZGthc3NlLm5ldCByb290IENBIHRlc3QwHhcNMjUwNzE0MDk1MDUxWhcNMjkxMjE2MDk1MDUxWjBrMRgwFgYDVQRhEw9OVFJOTy05OTE4MjU4MjcxCzAJBgNVBAYTAm5vMQ8wDQYDVQQLEwZEaWdkaXIxMTAvBgNVBAMTKGVpZGFzMnNhbmRrYXNzZSBQdWIgRUFBIFByb3ZpZGVyIENBIHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS+7CQFU3oWwu9dxauSvk5Xc7AeDhDtLb/x8WcUWFvlG4ekHKlqvW9gxe+W4KJrfn95UZ/0fOfm+znsha/zpiMKo4H8MIH5MFEGCCsGAQUFBwEBBEUwQzBBBggrBgEFBQcwAoY1aHR0cHM6Ly9jYS50ZXN0LmVpZGFzMnNhbmRrYXNzZS5uZXQvdjEvY2VydHMvcm9vdC5jZXIwHQYDVR0OBBYEFD/oYNwZ6+S0FLt9IQvCHPFK6ktiMA4GA1UdDwEB/wQEAwIBBjAMBgNVHRMEBTADAQH/MEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHBzOi8vY2EudGVzdC5laWRhczJzYW5ka2Fzc2UubmV0L3YxL2NlcnRzL3Jvb3QuY3JsMB8GA1UdIwQYMBaAFAovxv8fWdbiQFZRag96JzV3JazxMAoGCCqGSM49BAMDA0gAMEUCIHcgPyDKaizjJPpyztDqUwVqDabzOBVSQwgFIAFT+aV+AiEA8sFi8APxqLmwmCjd5EOd2WhGXSWRksIcCW+aS8kpPmU="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "AMA - Agência para a Modernização Administrativa"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATPT-98765"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "2345",
                    "Country": "PT"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain.pt"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+35134567"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.pt"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/PT"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_pt"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIC3zCCAoWgAwIBAgIUcSydOyasuB5uNjr9rj5tPAhpbQUwCgYIKoZIzj0EAwIwejEtMCsGA1UEAwwkRW1pc3NvciBkZSBQSUQgLSBDZXJ0aWZpY2FkbyByYWl6IDAxMTwwOgYDVQQKDDNBTUEgLSBBZ8OqbmNpYSBwYXJhIGEgTW9kZXJuaXphw6fDo28gQWRtaW5pc3RyYXRpdmExCzAJBgNVBAYTAlBUMB4XDTI0MDgyMzE4MTQ0N1oXDTMzMTExOTE4MTQ0NlowejEtMCsGA1UEAwwkRW1pc3NvciBkZSBQSUQgLSBDZXJ0aWZpY2FkbyByYWl6IDAxMTwwOgYDVQQKDDNBTUEgLSBBZ8OqbmNpYSBwYXJhIGEgTW9kZXJuaXphw6fDo28gQWRtaW5pc3RyYXRpdmExCzAJBgNVBAYTAlBUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJQQp1ekgl4ztbyvAEHQcHjiIwNRbELpVBzqXiGP2AZdhCP0qgEQ5Ud2hb0fbrE2/hEtiZmw0ppGX37g/wx+VLaOB6DCB5TASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFNl5BlM1kkgig634oJOTlZRNJbezMBYGA1UdJQEB/wQMMAoGCCuBAgIAAAEHMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuYW1hLnByb2pqLmV1L2NybC9waWRfQ0FfMDEuY3JsMB0GA1UdDgQWBBTZeQZTNZJIIoOt+KCTk5WUTSW3szAOBgNVHQ8BAf8EBAMCAQYwIgYDVR0SBBswVIZSaHR0cHM6Ly93d3cuYW1hLmdvdi5wdC8wCgYIKoZIzj0EAwIDSAAwRQIhAPlr1TTIv8pTKOY08FpKrpNsFLj9gKIagDIUHcDPjy6iAiBL8GUS5H5NcHhTEjJxxEMX9CVuFfVhvRCssbaCV3RwsA=="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "A-SIT"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATAT-45678"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "2345",
                    "Country": "AT"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain.at"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+4378901"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.at"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/AT"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_at_1"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICGzCCAcCgAwIBAgIUb9GJdqQMdwXaoO61uxoBlg+jhbYwCgYIKoZIzj0EAwIwLDELMAkGA1UEBhMCQVQxDjAMBgNVBAoMBUEtU0lUMQ0wCwYDVQQDDARJQUNBMB4XDTI1MDQwNzA5NDQ1N1oXDTI2MDQwNzA5NDQ1N1owLDELMAkGA1UEBhMCQVQxDjAMBgNVBAoMBUEtU0lUMQ0wCwYDVQQDDARJQUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElIXOzb+iF+zGutygdIVOBnC4R6OvhYo5TGWhrH0idmqs56IVwJWYzQYzK4CbYePcxpMQY3lKBa5O0MAZe+EogKOBvzCBvDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAiBgNVHRIEGzAZhhdodHRwczovL3dhbGxldC5hLXNpdC5hdDAyBgNVHR8EKzApMCegJaAjhiFodHRwczovL3dhbGxldC5hLXNpdC5hdC9jcmwvMS5jcmwwHwYDVR0jBBgwFoAUDQF5K46YVgzLpfV5stoutBezK6QwHQYDVR0OBBYEFA0BeSuOmFYMy6X1ebLaLrQXsyukMAoGCCqGSM49BAMCA0kAMEYCIQCz0i9GA24ZOf3Wk+w8+09J6ARAHKLuBuepszBxVZdaZAIhAJlgzKBhHw8+Bwr+wLGQVjMC5e9BWWaUga8ZP9dRYhHJ"
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "ISO Root CA"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATAT-0987"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "2345",
                    "Country": "AT"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain2.at"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+3320390"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.at"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/AT"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_at_2"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICbDCCAhKgAwIBAgIUH23VY4YX6sFgbdidaIr2o7cR154wCgYIKoZIzj0EAwIwIzELMAkGA1UEBhMCQVQxFDASBgNVBAMMC0lTTyBSb290IENBMB4XDTI1MDUyODExNTMxMloXDTM1MDUyNjExNTMxMlowIzELMAkGA1UEBhMCQVQxFDASBgNVBAMMC0lTTyBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEisG5+9ei6IRPnTkc2HuiY5kDWM+SUEeTkDXBs7bz/Xc1gwa0WbfEwJA2GuasCl4h0Zzv2fuDK+ER2+Gb7IsPWKOCASIwggEeMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTeJAquS8H45Kv/lng41lul7kTOCDAfBgNVHSMEGDAWgBTeJAquS8H45Kv/lng41lul7kTOCDCBiwYDVR0fBIGDMIGAMH6gfKB6hnhodHRwczovL3ZhdWx0LmxpZS1pbnRlcm5hbC5wcm9kdWN0aW9uLmNsdXN0ZXJzLnlvdW5pcXguY29tL3YxL21hbmFnZWQvcGtpL21pYS1saWUtaW50ZXJuYWwvbWlhLWxpZS1pbnRlcm5hbC1pc28tcm9vdC9jcmwwKgYDVR0SBCMwIYEfdGVhbS5xdWFudHVtcXVva2thc0B5b3VuaXF4LmNvbTAKBggqhkjOPQQDAgNIADBFAiA9ehNPI3Ck4bfcma27BbKClYLOmjIbu0ytFf6etfp5dwIhAIZT1olmq8bVm7iDRjtFAWUUpNjKQMPAXXY83EbqiqQV"
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Bundesdruckerei GmbH"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATDE-12345"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "2345",
                    "Country": "DE"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain.de"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+49320390"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.de"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/DE"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_de_1"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICNTCCAdygAwIBAgIUBEfh5TdWaKkeiOkVBHKBHe7VHOUwCgYIKoZIzj0EAwIwZzELMAkGA1UEBhMCREUxDzANBgNVBAcMBkJlcmxpbjEdMBsGA1UECgwUQnVuZGVzZHJ1Y2tlcmVpIEdtYkgxETAPBgNVBAsMCFQgQ1MgSURFMRUwEwYDVQQDDAxQSURQIERlbW8gQ0EwHhcNMjUxMTE5MTIwNjMwWhcNMzUxMTE3MTIwNjMwWjBnMQswCQYDVQQGEwJERTEPMA0GA1UEBwwGQmVybGluMR0wGwYDVQQKDBRCdW5kZXNkcnVja2VyZWkgR21iSDERMA8GA1UECwwIVCBDUyBJREUxFTATBgNVBAMMDFBJRFAgRGVtbyBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLfzEvVnrtzbM47MtwES2H4cOFtqvaZEQw4DGMiENSbfKih9WxxhDN8HzuukmiFZYhOxy0frbPlCBJkhGZFsKOWjZjBkMB0GA1UdDgQWBBSAX87IYWUcmGz01ZRdX/qAWEO+XzAfBgNVHSMEGDAWgBSAX87IYWUcmGz01ZRdX/qAWEO+XzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNHADBEAiBae8hSEdl3gqo8gmbvl9IV9rTrG5iw/6kk6h8w0upuVwIgM29abFnlKUY07mil1xc43zoMqql4YuWv29VHA9ZiT4Y="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Microsec Ltd."
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATHU-23584497"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "23451",
                    "Country": "HU"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain.hu"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+3698709"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.hu"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/HU"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_hu_1"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDQzCCAuigAwIBAgIMBcKMJXgy2272WHQKMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UECgwNTWljcm9zZWMgTHRkLjEXMBUGA1UEYQwOVkFUSFUtMjM1ODQ0OTcxIzAhBgNVBAMMGlRlc3QgZS1Temlnbm8gUm9vdCBDQSAyMDE3MB4XDTE3MDkyMjIwMDAwMFoXDTQyMDkyMjA2MDAwMFowcTELMAkGA1UEBhMCSFUxETAPBgNVBAcMCEJ1ZGFwZXN0MRYwFAYDVQQKDA1NaWNyb3NlYyBMdGQuMRcwFQYDVQRhDA5WQVRIVS0yMzU4NDQ5NzEeMBwGA1UEAwwVVGVzdCBlLVN6aWdubyBDQSAyMDE3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElKYzOPtAdd2ohSfwEgX2A+Zr2jXWrEqAwJYRs9aBjxT67VwuD10R+TEY0aRwzbrAAPfR2hsOr9DcvZlh4AXRraOCAV8wggFbMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMD4GA1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwOi8vdGVzenQuZS1zemlnbm8uaHUvcWNwczAdBgNVHQ4EFgQUeptoh454hhbzt/k2HvgamLNkHIkwHwYDVR0jBBgwFoAUklDZBPHkz7JSHyQKgYTiOO2dO44wOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL3Rlc3p0LmUtc3ppZ25vLmh1L3Ryb290Y2EyMDE3LmNybDB9BggrBgEFBQcBAQRxMG8wNwYIKwYBBQUHMAGGK2h0dHA6Ly90ZXN6dC5lLXN6aWduby5odS90ZXN0cm9vdGNhMjAxN29jc3AwNAYIKwYBBQUHMAKGKGh0dHA6Ly90ZXN6dC5lLXN6aWduby5odS90cm9vdGNhMjAxNy5jcnQwCgYIKoZIzj0EAwIDSQAwRgIhAL+F7BHEDUvV/weTnf4TwzwDIssl0hMF/0oKo0c9CaXXAiEAvNpfSAJjlU9kCqsRVUYVQqVffJCuBPIKdFvfcejwfbY="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "TEST Authority"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATEE-12345"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "23451",
                    "Country": "EE"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@domain.ee"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+37298709"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.ee"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/EE"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_ee"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICiTCCAjCgAwIBAgIUD89WCelKX+PFzZTKvrIsMgoIjZcwCgYIKoZIzj0EAwIwUjELMAkGA1UEBhMCRUUxDjAMBgNVBAgMBUhhcmp1MRcwFQYDVQQKDA5URVNUIEF1dGhvcml0eTEaMBgGA1UEAwwRVEVTVCBJQUNBIFJvb3QgQ0EwHhcNMjUwMjE5MTExNDI2WhcNNDUwMjE0MTExNDI2WjBSMQswCQYDVQQGEwJFRTEOMAwGA1UECAwFSGFyanUxFzAVBgNVBAoMDlRFU1QgQXV0aG9yaXR5MRowGAYDVQQDDBFURVNUIElBQ0EgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOJyw8+GgiTyqkzhvwA5nNMwsjLA24/2wjYrXJMb23fCAWeskZu014znoXZHJZK+cxlnvLtLscYCiF7REr6NWcqjgeMwgeAwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFHAddh/lzBAlZm1hAO/QgQmhV9WBMCMGA1UdEgQcMBqBGGNvbnRhY3RAaWFjYS5leGFtcGxlLmNvbTB2BgNVHR8EbzBtMGugaaBnhmVodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vb3Blbi1laWQvZXVkaS1xZWFhLWlzc3Vlci1wb2MvcmVmcy9oZWFkcy9kZXZlbG9wL2xvY2FsL2NybC9pYWNhLmNybDAKBggqhkjOPQQDAgNHADBEAiBt84QP49zoXBFItKhxIPkg+7qXbf6eIMY0xkc1M7RYlQIgWOSUJbP8KEreKUQ5Nwgae13YifG3jpJfU+nVWAe+1Ik="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "GRNET"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "VATEL-77432"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Rue test",
                    "Locality": "test",
                    "StateOrProvince": "test",
                    "PostalCode": "53554",
                    "Country": "EL"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test2@domain.el"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+30293239487"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://test.el"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/EL"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "name_pid_solution_el"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIICkTCCAjigAwIBAgIUBHi4ixVY+v67hn64ELqWc/cuIoQwCgYIKoZIzj0EAwIwPTEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIEdSIDAxMQ4wDAYDVQQKDAVHUk5FVDELMAkGA1UEBhMCR1IwHhcNMjUxMTAzMTMwMzQ1WhcNMjYxMTAzMTMwMzQ1WjA9MR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gR1IgMDExDjAMBgNVBAoMBUdSTkVUMQswCQYDVQQGEwJHUjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGV76duOyXnqudRE1nzJHu4TF/hQLSzrUNNj/g14e1eno+mdF/2BUsTKMMoVi6Nvahco45gI0aC/sXBK+zfhysmjggEUMIIBEDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBQ9fVq9ZifBrdIV1gL89UMxFC+HyzBiBgNVHSMEWzBZoUGkPzA9MR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gR1IgMDExDjAMBgNVBAoMBUdSTkVUMQswCQYDVQQGEwJHUoIUBHi4ixVY+v67hn64ELqWc/cuIoQwFgYDVR0lAQH/BAwwCgYIK4ECAgAAAQcwMgYDVR0fBCswKTAnoCWgI4YhaHR0cDovLzgzLjIxMi43Mi4xMTQ6ODA4Mi9jcmwucGVtMA4GA1UdDwEB/wQEAwIBBjAbBgNVHRIEFDAShhBodHRwczovL2dybmV0LmdyMAoGCCqGSM49BAMCA0cAMEQCICAFSFanRww3RVPLqp4IC+/1JxXF9q3qE22t0R0pSKxUAiAJLUpXIknyy2qAwukAZujeuZne71PJ1Yh9xYjUdQZuhQ=="
                      }
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "PID Provider1"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "PAAP Test Name1"
                },
                {
                  "lang": "en",
                  "value": "VATPL-5170359458"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Test",
                    "Locality": "Locality",
                    "StateOrProvince": "",
                    "PostalCode": "",
                    "Country": "PL"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:test@test.se"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+9988"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "http://test"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/PL"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "Test Service 1"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDUTCCAjmgAwIBAgIQNx1PCl0yvLFIAPW3ueQiwzANBgkqhkiG9w0BAQsFADAvMRYwFAYDVQQKDA1QSUQgUHJvdmlkZXIxMRUwEwYDVQQDDAxOYW1lVGVzdENlcnQwHhcNMjUwOTI1MTQxNzUwWhcNMjYwOTI1MTQyNzUwWjAvMRYwFAYDVQQKDA1QSUQgUHJvdmlkZXIxMRUwEwYDVQQDDAxOYW1lVGVzdENlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCX9gPZbuZHoJQbrxXOtIWYiQw5a1DgSKe4h3MNXiE7728oHYHIhV0ZoU3SX70XJpWrNsudo7bVMLoHN2UANkjX6SO5LR1OL7oAo3NFD9974GlQxLg5QmrJacbgg1NtFLTHq5c8SLzG3fHc9DJ94vB/lGxP7rBBOzQLp3j9h1muLYl+ZGroZjZOj7d7uK0hK0d4UWkDWb2n2K6kC1PN7zwTLxchEF1oppPFjogF/7Gq7OWFiQy3LS6h+marlY6FxFmU9tq7Uu2hxJF2tFMPVZsMUHEluUZFW25VH30Y3LtiSvlRQY1wiakTuE2pRF3VvXi3Kgx2O15VdvbCadZOK/8hAgMBAAGjaTBnMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwFwYDVR0RBBAwDoIMTmFtZVRlc3RDZXJ0MB0GA1UdDgQWBBSKjzSwKcYg/s+/jOq+rm0NhUDC1DANBgkqhkiG9w0BAQsFAAOCAQEARyAF6yKL2xVPRVIA/o+YBdEmTRpnFAIPIvjC6hCfKpTz/hpMzHuuuTxU8oMg6mHyeL6fOGhLodXQMqkoJZMEpOwftnpHmIXR5+BHZaH7/Ga/6zIa53suiqydmuEo+FxDrBK6s42v/O2mB66hptTJ3cg3aqXEXeV5w5uAbTLlrCpaggXFBjZuR3E8xj8MGax4BUL8mBW+24XaRA/APSPnLwVlyJ95kiJC9R/9MH1t7wRxfftI7wuqQLi4hb3Nl/Zo1aL66txelX/TLkdq4f+1Ql1Pfzz60nIqk3oICCSg89acEx6o1tAfguBid50cHnLxaTBe6g8KFwXv+5PUTZ1Fug=="
                      }
                    ],
                    "X509SKIs": [
                      "io80sCnGIP7Pv4zqvq5tDYVAwtQ="
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              },
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "Test Service 2"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDNjCCAh6gAwIBAgIQXRnxamTIT4JGgTnOaCBRQjANBgkqhkiG9w0BAQsFADAuMRgwFgYDVQQKDA9QQUFQIFRlc3QgTmFtZTExEjAQBgNVBAMMCVRlc3RDZXJ0MTAeFw0yNTA5MTgxMDM2MDFaFw0zMDA5MTgxMDQ2MDFaMC4xGDAWBgNVBAoMD1BBQVAgVGVzdCBOYW1lMTESMBAGA1UEAwwJVGVzdENlcnQxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlLCnGRUwbkiOcFnI9f7CFfFzxOfsgNkI6x/S7BXrTesp+VgP/PPO+yILV42kNBDFO+YUcd5T9Offv+s6YfU1YfTCh1D4UXio9s9b8iYFiRCkB7s5bqHAYb9uc2zDpt/t+heuRt7TjGGJqdykpRRjcNP56TMtqfmhtQhvG1LYJzj1HulsmjGvdJVSkreeOxkzy4GCB/6UENqnWZhPdGvqY5tzZ2GXUwpN7mDFP1zA5unLgVQIcHmXtWYAYllnNu7IV9mBq/g1XvngzyWefMmKLqf791AgXY0dd9G6JlOOvkB5Y4jMHAT6DzNyoYiQrigTQxI2lWyuqYxTqhhY201wqQIDAQABo1AwTjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBTlGtpzx3x9ErCwLv73FslxFD6IPTANBgkqhkiG9w0BAQsFAAOCAQEAUQZ5Qeb8mcZpMub4I5NF5bNox3yVPwPThzf6VwBVvaaHsm2xZoWXSpKBlyiCmFoQINJ5PHglgZOIVdcCU3SKfeHhffLhxIW+qTC6DZ05DZyuL4+FFVMH8/SKOrlLbT3x1SM5u8iEWMFPFMfkGDW8Xq6vWpobuDg5eVyYjvj29wCZuyygfaj1cRr21/aKefOksw8rc97yTzzHNPcHjjBqFZv8Pq4TAMExgV0a6h8tnnk8AK2+MSy0SOHbrCj7khm2Q5+gOaPXfwzVHCoJTuEfRDSF96+IlX/2nr+eVwvpfcMtr+01LnRh/actoLGOybsM/1H9jMGxF4VqsQwBiMwfxQ=="
                      }
                    ],
                    "X509SKIs": [
                      "5Rrac8d8fRKwsC7+9xbJcRQ+iD0="
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                  "ServiceSupplyPoints": [
                    {
                      "uriValue": "https://supplypoints",
                      "ServiceType": "type:type"
                    }
                  ],
                  "ServiceDefinitionURI": [
                    {
                      "lang": "en",
                      "uriValue": "information:uri"
                    }
                  ]
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Liechtenstein National Administration"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "Principality of Lichtenstein"
                },
                {
                  "lang": "en",
                  "value": "VATLI-987654"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Platz 1",
                    "Locality": "Vaduz",
                    "StateOrProvince": "Liechtenstein",
                    "PostalCode": "FL-000",
                    "Country": "LI"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:office@test.li"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+4235002211"
                  },
                  {
                    "lang": "en",
                    "uriValue": "https://www.llv.li/en/"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://www.llv.li/en/policies"
                },
                {
                  "lang": "en",
                  "uriValue": "https://www.llv.li/en/information"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/LI"
                }
              ],
              "TEInformationExtensions": [
                {
                  "OtherAssociatedBodies": [
                    {
                      "AssociatedBodyName": [
                        {
                          "lang": "en",
                          "value": "Liechtenstein National Administration PID Body"
                        }
                      ],
                      "AssociatedBodyTradeName": [
                        {
                          "lang": "en",
                          "value": "Principality of Lichtenstein PID Body"
                        },
                        {
                          "lang": "en",
                          "value": "VATLI-200100"
                        }
                      ],
                      "AssociatedBodyAddress": {
                        "AssociatedBodyPostalAddress": [
                          {
                            "lang": "en",
                            "StreetAddress": "Platz 2",
                            "Locality": "Vaduz",
                            "StateOrProvince": "Liechtenstein",
                            "PostalCode": "FL-000",
                            "Country": "LI"
                          }
                        ],
                        "AssociatedBodyElectronicAddress": [
                          {
                            "lang": "en",
                            "uriValue": "mailto:office-PID-Body@test.li"
                          },
                          {
                            "lang": "en",
                            "uriValue": "tel:+4235002212"
                          },
                          {
                            "lang": "en",
                            "uriValue": "https://www.llv.li/en/pid"
                          }
                        ]
                      },
                      "AssociatedBodyInformationURI": [
                        {
                          "lang": "en",
                          "uriValue": "https://www.llv.li/en/pid/information"
                        }
                      ]
                    }
                  ]
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "PID Service 1"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIDsjCCApqgAwIBAgIQa5/PTwD9epxBQHrl6XObezANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJMSTEOMAwGA1UEBwwFVmFkdXoxDDAKBgNVBAsMA0xMVjEuMCwGA1UECgwlTGllY2h0ZW5zdGVpbiBOYXRpb25hbCBBZG1pbmlzdHJhdGlvbjEPMA0GA1UEAwwGbGx2LmxpMB4XDTI2MDEwNTEzMTkyMFoXDTI3MDEwNTEzMTk1MFowbDELMAkGA1UEBhMCTEkxDjAMBgNVBAcMBVZhZHV6MQwwCgYDVQQLDANMTFYxLjAsBgNVBAoMJUxpZWNodGVuc3RlaW4gTmF0aW9uYWwgQWRtaW5pc3RyYXRpb24xDzANBgNVBAMMBmxsdi5saTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJtDK/L1QEAj7QNtAgA5SNVXXahMtwayCAHtimJEGMRXeiI9KSE+BBfQ8c989Wbw9KqLsIUWGNuleGQCRFWArZmWXXezHn3fJecpeb06t+OZiPaLgq4iBp8EZ0czGFIxNxXOtSSgVcL1FCsDnIW9yzRt/xFPUn/59F6oGky/KPQXg0sW3UOkTW/k795QqIvLaMPFKn1kKkBSGh4TWmp6zQ0c7lEWGLKlCV0l0XHQAwl0bmoebEsA7QBG320i31n4Gr5y0zCbWjxEv3IU6RWZ2QARlybj4lVXyTyiezJ91v2tEhWlE/xK6AV7y9N5IcB5e+sxKDmjCp4gb1idBJYM9W0CAwEAAaNQME4wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQU0RI/MTHeLnYjg8CQlPsrBXvWZLkwDQYJKoZIhvcNAQELBQADggEBAHlLN3fEK8q9mk5Uy6Y0Bnq7clLKAlajbUcPc2/SAiYsmioNv5k6p6dAiNXng4gaSe1gGQz9o15raYz2EK3nfmw1ooFjXjmZOfiY2EBsBd9X3EJCu2aYBDeOaX3Xqw1s0ZXdfmDnvqEEmVvVr+VubzX8JLS2AM2glyRvBb7w27gBBvptggS54P9Re16yGxiQbqV17k8h/0idYbGH31Y8lUYRyOHkFtlL4pqJmCQ38laej0L73GiUtCg0hdrGcrEf2oziO55pBpsJTAiiCkv/Pz7Ri4o8l3ALQKrByloO2mpwlPmVmxxNi/o79XFGelTIBrWIVYgBbTwfDzvQIIKjY6I="
                      }
                    ],
                    "X509SKIs": [
                      "0RI/MTHeLnYjg8CQlPsrBXvWZLk="
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                  "ServiceSupplyPoints": [
                    {
                      "uriValue": "https://www.llv.li/en/pid/service/supply",
                      "ServiceType": "https://www.llv.li/en/pid/service/supply/type"
                    }
                  ],
                  "ServiceDefinitionURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://www.llv.li/en/pid/service/information"
                    }
                  ]
                }
              }
            ]
          },
          {
            "TrustedEntityInformation": {
              "TEName": [
                {
                  "lang": "en",
                  "value": "Reference implementation TEST EU PID Provider"
                }
              ],
              "TETradeName": [
                {
                  "lang": "en",
                  "value": "EUDI Wallet Reference Implementation"
                },
                {
                  "lang": "en",
                  "value": "VATFR-000000"
                }
              ],
              "TEAddress": {
                "TEPostalAddress": [
                  {
                    "lang": "en",
                    "StreetAddress": "Street",
                    "Locality": "",
                    "StateOrProvince": "",
                    "PostalCode": "",
                    "Country": "FR"
                  }
                ],
                "TEElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:email@address.fr"
                  },
                  {
                    "lang": "en",
                    "uriValue": "tel:+3520000"
                  }
                ]
              },
              "TEInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://website.fr"
                },
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/PIDProvider/FR"
                }
              ]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "EU PID Issuance"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIC0zCCAnmgAwIBAgIUXRXxkLbUM6+njr/XT0IIw/HA/uowCgYIKoZIzj0EAwMwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJFVTAeFw0yNTA0MDkwMDAzMzBaFw0zNDA3MDYwMDAzMjlaMFcxGTAXBgNVBAMMEFBJRCBJc3N1ZXIgQ0EgMDIxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCRVUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkqdLmwIlv+SSWr00tAIrt7EAMztgd3w9qA6qEm16yVfsLcyx2f4oIWuH45wa37J9GoNWpdeo27VoSoNMCzxOYo4IBITCCAR0wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRCUFC+ELgQ8J1EXI2/qxAI7ifcSTATBgNVHSUEDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX0VVXzAyLmNybDAdBgNVHQ4EFgQUQlBQvhC4EPCdRFyNv6sQCO4n3EkwDgYDVR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDSAAwRQIhAIavYfC5o0VVLKfgTKkzzWgc09hzDMsCl3O2le2sQfG7AiA2soqAN5gtUOLQKWK00DUz22EW79rvaV+VJPvfdQeokA=="
                      }
                    ],
                    "X509SKIs": [
                      "QlBQvhC4EPCdRFyNv6sQCO4n3Ek="
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance"
                }
              },
              {
                "ServiceInformation": {
                  "ServiceName": [
                    {
                      "lang": "en",
                      "value": "EU PID Revocation"
                    }
                  ],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [
                      {
                        "val": "MIIC0zCCAnmgAwIBAgIUXRXxkLbUM6+njr/XT0IIw/HA/uowCgYIKoZIzj0EAwMwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJFVTAeFw0yNTA0MDkwMDAzMzBaFw0zNDA3MDYwMDAzMjlaMFcxGTAXBgNVBAMMEFBJRCBJc3N1ZXIgQ0EgMDIxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCRVUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkqdLmwIlv+SSWr00tAIrt7EAMztgd3w9qA6qEm16yVfsLcyx2f4oIWuH45wa37J9GoNWpdeo27VoSoNMCzxOYo4IBITCCAR0wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRCUFC+ELgQ8J1EXI2/qxAI7ifcSTATBgNVHSUEDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX0VVXzAyLmNybDAdBgNVHQ4EFgQUQlBQvhC4EPCdRFyNv6sQCO4n3EkwDgYDVR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDSAAwRQIhAIavYfC5o0VVLKfgTKkzzWgc09hzDMsCl3O2le2sQfG7AiA2soqAN5gtUOLQKWK00DUz22EW79rvaV+VJPvfdQeokA=="
                      }
                    ],
                    "X509SKIs": [
                      "QlBQvhC4EPCdRFyNv6sQCO4n3Ek="
                    ]
                  },
                  "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Revocation"
                }
              }
            ]
          }
        ]
      }
    """.trimIndent()

    val wrpacProvidersOriginal = """
          {
            "ListAndSchemeInformation": {
              "LoTEVersionIdentifier": 1,
              "LoTESequenceNumber": 2,
              "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList",
              "SchemeOperatorName": [
                {
                  "lang": "en",
                  "value": "European Commission"
                },
                {
                  "lang": "bg",
                  "value": "Европейска комисия"
                },
                {
                  "lang": "es",
                  "value": "Comisión Europea"
                },
                {
                  "lang": "cs",
                  "value": "Evropská komise"
                },
                {
                  "lang": "da",
                  "value": "Europa-Kommissionen"
                },
                {
                  "lang": "de",
                  "value": "Europäische Kommission"
                },
                {
                  "lang": "et",
                  "value": "Euroopa Komisjon"
                },
                {
                  "lang": "el",
                  "value": "Ευρωπαϊκή Επιτροπή"
                },
                {
                  "lang": "fr",
                  "value": "Commission européenne"
                },
                {
                  "lang": "it",
                  "value": "Commissione europea"
                },
                {
                  "lang": "lv",
                  "value": "Eiropas Komisija"
                },
                {
                  "lang": "lt",
                  "value": "Europos Komisija"
                },
                {
                  "lang": "hu",
                  "value": "Európai Bizottság"
                },
                {
                  "lang": "mt",
                  "value": "Il-Kummissjoni Ewropea"
                },
                {
                  "lang": "nl",
                  "value": "Europese Commissie"
                },
                {
                  "lang": "pl",
                  "value": "Komisja Europejska"
                },
                {
                  "lang": "pt",
                  "value": "Comissão Europeia"
                },
                {
                  "lang": "ro",
                  "value": "Comisia Europeană"
                },
                {
                  "lang": "sk",
                  "value": "Európska komisia"
                },
                {
                  "lang": "sl",
                  "value": "Evropska komisija"
                },
                {
                  "lang": "fi",
                  "value": "Euroopan komissio"
                },
                {
                  "lang": "sv",
                  "value": "Europeiska kommissionen"
                },
                {
                  "lang": "hr",
                  "value": "Europska komisija"
                }
              ],
              "SchemeOperatorAddress": {
                "SchemeOperatorPostalAddress": [
                  {
                    "lang": "fr",
                    "StreetAddress": "Rue de la Loi 200",
                    "Locality": "Bruxelles",
                    "PostalCode": "1049",
                    "Country": "BE"
                  },
                  {
                    "lang": "nl",
                    "StreetAddress": "Wetstraat 200",
                    "Locality": "Brussel",
                    "PostalCode": "1049",
                    "Country": "BE"
                  },
                  {
                    "lang": "en",
                    "StreetAddress": "Rue de la Loi/Wetstraat 200",
                    "Locality": "Brussels",
                    "PostalCode": "1049",
                    "Country": "BE"
                  }
                ],
                "SchemeOperatorElectronicAddress": [
                  {
                    "lang": "en",
                    "uriValue": "mailto:DIGIT-EU-TRUST-NON-PROD@ec.europa.eu"
                  },
                  {
                    "lang": "en",
                    "uriValue": "https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists"
                  }
                ]
              },
              "SchemeName": [
                {
                  "lang": "en",
                  "value": "The present list is a list of person identifier providers of EUDI Wallet issued in accordance with CIR 2024/2980"
                }
              ],
              "SchemeInformationURI": [
                {
                  "lang": "en",
                  "uriValue": "https://trust.tech.ec.europa.eu/lists/eudiw/wrpac-providers-list-scheme-information"
                }
              ],
              "StatusDeterminationApproach": "http://uri.etsi.org/19602/WRPACProvidersList/StatusDetn/EU",
              "SchemeTypeCommunityRules": [
                {
                  "lang": "en",
                  "uriValue": "http://uri.etsi.org/19602/WRPACProvidersList/schemerules/EU"
                }
              ],
              "SchemeTerritory": "EU",
              "PolicyOrLegalNotice": [
                {
                  "LoTEPolicy": {
                    "lang": "en",
                    "uriValue": "http://trust.tech.ec.europa.eu/lists/eudiw/legal-notice#EN"
                  }
                }
              ],
              "ListIssueDateTime": "2026-04-02T09:21:34Z",
              "NextUpdate": "2026-10-01T09:21:34Z"
            },
            "TrustedEntitiesList": [
              {
                "TrustedEntityInformation": {
                  "TEName": [
                    {
                      "lang": "en",
                      "value": "eidas2sandkasse RP Access CA test"
                    }
                  ],
                  "TETradeName": [
                    {
                      "lang": "en",
                      "value": "NTRNO-991825827"
                    }
                  ],
                  "TEAddress": {
                    "TEPostalAddress": [
                      {
                        "lang": "en",
                        "StreetAddress": "Rue test",
                        "Locality": "test",
                        "StateOrProvince": "test",
                        "PostalCode": "1234",
                        "Country": "NO"
                      }
                    ],
                    "TEElectronicAddress": [
                      {
                        "lang": "en",
                        "uriValue": "mailto:test@domain.no"
                      },
                      {
                        "lang": "en",
                        "uriValue": "tel:+47987654"
                      }
                    ]
                  },
                  "TEInformationURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://test.no"
                    },
                    {
                      "lang": "en",
                      "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/NO"
                    }
                  ]
                },
                "TrustedEntityServices": [
                  {
                    "ServiceInformation": {
                      "ServiceName": [
                        {
                          "lang": "en",
                          "value": "name_wrpac_solution_no"
                        }
                      ],
                      "ServiceDigitalIdentity": {
                        "X509Certificates": [
                          {
                            "val": "MIICuzCCAmGgAwIBAgIJAKcp7ByPxFNUMAoGCCqGSM49BAMDMGMxGDAWBgNVBGETD05UUk5PLTk5MTgyNTgyNzELMAkGA1UEBhMCbm8xDzANBgNVBAsTBkRpZ2RpcjEpMCcGA1UEAxMgZWlkYXMyc2FuZGthc3NlLm5ldCByb290IENBIHRlc3QwHhcNMjUwNTA5MDc1NjU0WhcNMzAwNDI5MDc1NjU0WjBkMRgwFgYDVQRhEw9OVFJOTy05OTE4MjU4MjcxCzAJBgNVBAYTAm5vMQ8wDQYDVQQLEwZEaWdkaXIxKjAoBgNVBAMTIWVpZGFzMnNhbmRrYXNzZSBSUCBBY2Nlc3MgQ0EgdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE4OQr5vpRMvcYZs46LkpdDgVQ9V+9E/Gx3Io2jqm+g/43/0b2Ns9oSRv1VpY/vYSI/O6JWylRQ+MNk6V3DfQv2jgfwwgfkwUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwczovL2NhLnRlc3QuZWlkYXMyc2FuZGthc3NlLm5ldC92MS9jZXJ0cy9yb290LmNlcjAdBgNVHQ4EFgQUUcgCJYAwgpE7JCLUm9xeoainXcwwDgYDVR0PAQH/BAQDAgEGMAwGA1UdEwQFMAMBAf8wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cHM6Ly9jYS50ZXN0LmVpZGFzMnNhbmRrYXNzZS5uZXQvdjEvY2VydHMvcm9vdC5jcmwwHwYDVR0jBBgwFoAUCi/G/x9Z1uJAVlFqD3onNXclrPEwCgYIKoZIzj0EAwMDSAAwRQIgfuk68h7gRHYXzBuddxFEUGl1eYtQgMCMKcw6D1kVjzgCIQC91xg+yGdocsoPmIGACivfYZAftiQXGEjHdid9RZOX1g=="
                          }
                        ]
                      },
                      "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
                    }
                  }
                ]
              },
              {
                "TrustedEntityInformation": {
                  "TEName": [
                    {
                      "lang": "en",
                      "value": "Idakto"
                    }
                  ],
                  "TETradeName": [
                    {
                      "lang": "en",
                      "value": "VATFR-12345"
                    }
                  ],
                  "TEAddress": {
                    "TEPostalAddress": [
                      {
                        "lang": "en",
                        "StreetAddress": "Rue test",
                        "Locality": "test",
                        "StateOrProvince": "test",
                        "PostalCode": "1234",
                        "Country": "FR"
                      }
                    ],
                    "TEElectronicAddress": [
                      {
                        "lang": "en",
                        "uriValue": "mailto:test@domain.fr"
                      },
                      {
                        "lang": "en",
                        "uriValue": "tel:+33234567"
                      }
                    ]
                  },
                  "TEInformationURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://test.fr"
                    },
                    {
                      "lang": "en",
                      "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/FR"
                    }
                  ]
                },
                "TrustedEntityServices": [
                  {
                    "ServiceInformation": {
                      "ServiceName": [
                        {
                          "lang": "en",
                          "value": "name_wrpac_solution_fr"
                        }
                      ],
                      "ServiceDigitalIdentity": {
                        "X509Certificates": [
                          {
                            "val": "MIICgjCCAiegAwIBAgIUafRAIleaQOm9jZLiIML9FeOWd9cwCgYIKoZIzj0EAwIwczELMAkGA1UEBhMCRlIxDzANBgNVBAgMBkZSQU5DRTEPMA0GA1UEBwwGQW5nZXJzMQ8wDQYDVQQKDAZJZGFrdG8xDjAMBgNVBAsMBVN0ZWFtMSEwHwYDVQQDDBhyZWFkZXItaXNzdWVyQGlkYWt0by5jb20wHhcNMjUwNzI1MTQ0NzI1WhcNMzAwNzI0MTQ0NzI1WjBzMQswCQYDVQQGEwJGUjEPMA0GA1UECAwGRlJBTkNFMQ8wDQYDVQQHDAZBbmdlcnMxDzANBgNVBAoMBklkYWt0bzEOMAwGA1UECwwFU3RlYW0xITAfBgNVBAMMGHJlYWRlci1pc3N1ZXJAaWRha3RvLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCq6dkUsfqjCByvS+UM/FDOgjO5fbB6aEesAgWmiMrSJQybQnAGSOySr0V+E0puM3eMaLy4DzsGLW0LX6J+vRLOjgZgwgZUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFJ57lkHy09w59xHQDk4y9ubmup5VMCsGA1UdEQQkMCKCIG9wZW5pZDR2cC5kcnVrcXMuYXNnYXJkLmlkZW52LmZyMCMGA1UdEgQcMBqBGHJlYWRlci1pc3N1ZXJAaWRha3RvLmNvbTAKBggqhkjOPQQDAgNJADBGAiEA9hIBNw8GI7E5z/NZI/3CUMZjndoKGg+2o0lh8/6gY30CIQCiUgMnIib46Ypi4IryQOn282zPWrTWQFwIebwASeG9+w=="
                          }
                        ]
                      },
                      "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
                    }
                  }
                ]
              },
              {
                "TrustedEntityInformation": {
                  "TEName": [
                    {
                      "lang": "en",
                      "value": "Microsec Ltd."
                    }
                  ],
                  "TETradeName": [
                    {
                      "lang": "en",
                      "value": "VATHU-23584497"
                    }
                  ],
                  "TEAddress": {
                    "TEPostalAddress": [
                      {
                        "lang": "en",
                        "StreetAddress": "Rue test",
                        "Locality": "test",
                        "StateOrProvince": "test",
                        "PostalCode": "2345",
                        "Country": "HU"
                      }
                    ],
                    "TEElectronicAddress": [
                      {
                        "lang": "en",
                        "uriValue": "mailto:test@domain.hu"
                      },
                      {
                        "lang": "en",
                        "uriValue": "tel:+36567890"
                      }
                    ]
                  },
                  "TEInformationURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://test.hu"
                    },
                    {
                      "lang": "en",
                      "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/HU"
                    }
                  ]
                },
                "TrustedEntityServices": [
                  {
                    "ServiceInformation": {
                      "ServiceName": [
                        {
                          "lang": "en",
                          "value": "name_wrpac_solution_hu"
                        }
                      ],
                      "ServiceDigitalIdentity": {
                        "X509Certificates": [
                          {
                            "val": "MIIDQzCCAuigAwIBAgIMBcKMJXgy2272WHQKMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEWMBQGA1UECgwNTWljcm9zZWMgTHRkLjEXMBUGA1UEYQwOVkFUSFUtMjM1ODQ0OTcxIzAhBgNVBAMMGlRlc3QgZS1Temlnbm8gUm9vdCBDQSAyMDE3MB4XDTE3MDkyMjIwMDAwMFoXDTQyMDkyMjA2MDAwMFowcTELMAkGA1UEBhMCSFUxETAPBgNVBAcMCEJ1ZGFwZXN0MRYwFAYDVQQKDA1NaWNyb3NlYyBMdGQuMRcwFQYDVQRhDA5WQVRIVS0yMzU4NDQ5NzEeMBwGA1UEAwwVVGVzdCBlLVN6aWdubyBDQSAyMDE3MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElKYzOPtAdd2ohSfwEgX2A+Zr2jXWrEqAwJYRs9aBjxT67VwuD10R+TEY0aRwzbrAAPfR2hsOr9DcvZlh4AXRraOCAV8wggFbMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMD4GA1UdIAQ3MDUwMwYEVR0gADArMCkGCCsGAQUFBwIBFh1odHRwOi8vdGVzenQuZS1zemlnbm8uaHUvcWNwczAdBgNVHQ4EFgQUeptoh454hhbzt/k2HvgamLNkHIkwHwYDVR0jBBgwFoAUklDZBPHkz7JSHyQKgYTiOO2dO44wOQYDVR0fBDIwMDAuoCygKoYoaHR0cDovL3Rlc3p0LmUtc3ppZ25vLmh1L3Ryb290Y2EyMDE3LmNybDB9BggrBgEFBQcBAQRxMG8wNwYIKwYBBQUHMAGGK2h0dHA6Ly90ZXN6dC5lLXN6aWduby5odS90ZXN0cm9vdGNhMjAxN29jc3AwNAYIKwYBBQUHMAKGKGh0dHA6Ly90ZXN6dC5lLXN6aWduby5odS90cm9vdGNhMjAxNy5jcnQwCgYIKoZIzj0EAwIDSQAwRgIhAL+F7BHEDUvV/weTnf4TwzwDIssl0hMF/0oKo0c9CaXXAiEAvNpfSAJjlU9kCqsRVUYVQqVffJCuBPIKdFvfcejwfbY="
                          }
                        ]
                      },
                      "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
                    }
                  }
                ]
              },
              {
                "TrustedEntityInformation": {
                  "TEName": [
                    {
                      "lang": "en",
                      "value": "A-SIT"
                    }
                  ],
                  "TETradeName": [
                    {
                      "lang": "en",
                      "value": "VATAT-45678"
                    }
                  ],
                  "TEAddress": {
                    "TEPostalAddress": [
                      {
                        "lang": "en",
                        "StreetAddress": "Rue test",
                        "Locality": "test",
                        "StateOrProvince": "test",
                        "PostalCode": "2345",
                        "Country": "AT"
                      }
                    ],
                    "TEElectronicAddress": [
                      {
                        "lang": "en",
                        "uriValue": "mailto:test@domain.at"
                      },
                      {
                        "lang": "en",
                        "uriValue": "tel:+43789012"
                      }
                    ]
                  },
                  "TEInformationURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://test.at"
                    },
                    {
                      "lang": "en",
                      "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/AT"
                    }
                  ]
                },
                "TrustedEntityServices": [
                  {
                    "ServiceInformation": {
                      "ServiceName": [
                        {
                          "lang": "en",
                          "value": "name_wrpac_solution_at"
                        }
                      ],
                      "ServiceDigitalIdentity": {
                        "X509Certificates": [
                          {
                            "val": "MIICJzCCAc6gAwIBAgIUSvMftn/oM3etHjE7hdIBl6tWMV8wCgYIKoZIzj0EAwIwMzELMAkGA1UEBhMCQVQxDjAMBgNVBAoMBUEtU0lUMRQwEgYDVQQDDAtWYWxlcmEgSUFDQTAeFw0yNTA2MjYwODI0MDJaFw0yNjA2MjYwODI0MDJaMDMxCzAJBgNVBAYTAkFUMQ4wDAYDVQQKDAVBLVNJVDEUMBIGA1UEAwwLVmFsZXJhIElBQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQmm+pmyUxx/x2eD131E8HhvNkhsfYQXzefZlxgLXQPqCOxO+VPOXVOKL0dUy+kHyT5IP/NOAh038coAVOgGPT4o4G/MIG8MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMCIGA1UdEgQbMBmGF2h0dHBzOi8vd2FsbGV0LmEtc2l0LmF0MDIGA1UdHwQrMCkwJ6AloCOGIWh0dHBzOi8vd2FsbGV0LmEtc2l0LmF0L2NybC8xLmNybDAfBgNVHSMEGDAWgBSDGoj0XuXE3qEVTmPvKSvIvR36ijAdBgNVHQ4EFgQUgxqI9F7lxN6hFU5j7ykryL0d+oowCgYIKoZIzj0EAwIDRwAwRAIgS9XcYA4Be5gDIdHmMOgJ3AeS44gT4bgVgsg/D5+WXS8CIAxJgi3nhGrVMj9SszehLorR2rR5FO5RZgITAaOIGSNP"
                          }
                        ]
                      },
                      "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance"
                    }
                  }
                ]
              },
              {
                "TrustedEntityInformation": {
                  "TEName": [
                    {
                      "lang": "en",
                      "value": "WRPAC Provider - failing conformance checks"
                    }
                  ],
                  "TETradeName": [
                    {
                      "lang": "en",
                      "value": "WRPAC Provider1"
                    },
                    {
                      "lang": "en",
                      "value": "VATLI-2345678"
                    }
                  ],
                  "TEAddress": {
                    "TEPostalAddress": [
                      {
                        "lang": "en",
                        "StreetAddress": "Platz 2",
                        "Locality": "Vaduz",
                        "StateOrProvince": "Liechtenstein",
                        "PostalCode": "Fl-001",
                        "Country": "PL"
                      }
                    ],
                    "TEElectronicAddress": [
                      {
                        "lang": "en",
                        "uriValue": "mailto:office-wrpac@test.li"
                      },
                      {
                        "lang": "en",
                        "uriValue": "tel:+423887744"
                      },
                      {
                        "lang": "en",
                        "uriValue": "https://www.llv.li/en/wrpac"
                      }
                    ]
                  },
                  "TEInformationURI": [
                    {
                      "lang": "en",
                      "uriValue": "https://www.llv.li/en/wrpac/policies"
                    },
                    {
                      "lang": "en",
                      "uriValue": "https://www.llv.li/en/wrpac/information"
                    },
                    {
                      "lang": "en",
                      "uriValue": "http://uri.etsi.org/19602/ListOfTrustedEntities/WRPACProvider/PL"
                    }
                  ]
                },
                "TrustedEntityServices": [
                  {
                    "ServiceInformation": {
                      "ServiceName": [
                        {
                          "lang": "en",
                          "value": "WRPAC Service 1"
                        }
                      ],
                      "ServiceDigitalIdentity": {
                        "X509Certificates": [
                          {
                            "val": "MIIDWjCCAkKgAwIBAgIQFNp7JHkUrblEFMsg3Z6PoDANBgkqhkiG9w0BAQsFADAxMRgwFgYDVQQKDA9XUlBBQyBQcm92aWRlcjExFTATBgNVBAMMDE5hbWVUZXN0Q2VydDAeFw0yNTA5MjUxNDMxMzhaFw0yNjA5MjUxNDQxMzhaMDExGDAWBgNVBAoMD1dSUEFDIFByb3ZpZGVyMTEVMBMGA1UEAwwMTmFtZVRlc3RDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsfg1O1Eq5tt92WJRylnFc75amIjPybG3yyATDg28rF1rBOcoGFXw/Za029VlewkYCGIznE3SyoaFTcO0e14MLW4sjvSAYYIwTfKFBo7X7VwbhI+ItVrb3bgNXUeLiq5eOerfZWthjtjB5p3SjOtOmIoHpRwRvegGrlFKFK7SFGt7iGMIxKEu0FDQOi7eJnPIhaMflE7qHDfgrX8YFrc8dgi8g062nk1JWM+g+eFcj/eCyHs3adWQ/P5yEVn/A5sOeO8W3tbxA98xRkHgZbikYPaYy1tQGWzdCxZ3kehyucBysaAOuoXunWjX/v4Tx0omEkVq5Dh+lt7iH2nyU03R+QIDAQABo24wbDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBwGA1UdEQQVMBOCEU5hbWVUZXN0Q2VydFdSUEFDMB0GA1UdDgQWBBToGtzqikCk196F3aaeq6HPxLfR3TANBgkqhkiG9w0BAQsFAAOCAQEAbqhUoauW+PRFiOO5O1QjF9pl7ncsCTL/13d4vnEmIicVOOHJjKnZ50/jGkVnPe34BaJ+iEVomNkEHg5XTaj005kTQ1Nimo9NCVJudl9v135dCPdSItGY2FRUfdesD0lYYwSEa0RUT57NeKA6ZTQNIlpE5HFywvKiktZ05GAFQuqn5UYMvaf2unEvXf6HO92yQcJ7H5A5zmJv5RBp6wFs2DznOTKdJMhjKOIybumDoXKCLQYqR9zDG042s369/UB/2FXcNfL3mi/VdayH2BwCu/OlyaxWy0pX+hhZuGEBbyrVTdJvsLSItsg7WpjxeU/GyViz227qh9xKCI/wCZmdzw=="
                          }
                        ]
                      },
                      "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
                      "ServiceSupplyPoints": [
                        {
                          "uriValue": "http://supply.points",
                          "ServiceType": "http://supply.pointstype"
                        }
                      ],
                      "ServiceDefinitionURI": [
                        {
                          "lang": "en",
                          "uriValue": "https://www.llv.li/en/wrpac/service/information"
                        }
                      ]
                    }
                  }
                ]
              }
            ]
          }
    """.trimIndent()

}

private val json = Json { ignoreUnknownKeys = true }
private fun lote(jsonTxt: String) = json.decodeFromString<ListOfTrustedEntities>(jsonTxt)

private val pidLote = lote(LoTETestData.pidProvidersPayload)
private val wrpacLote = lote(LoTETestData.wrpacProvidersOriginal)
private val filter = LoTEFilterService()

private fun issuanceCertsOf(lote: ListOfTrustedEntities, profile: LoteProfile) =
    filter.extractIssuanceCertificates(lote, profile).mapNotNull { it.certificate }

private fun certificateOf(
    lote: ListOfTrustedEntities,
    profile: LoteProfile,
    provider: String,
    kind: ServiceKind = ServiceKind.ISSUANCE,
): X509Certificate {
    val certs = when (kind) {
        ServiceKind.ISSUANCE -> filter.extractIssuanceCertificates(lote, profile)
        ServiceKind.REVOCATION -> filter.extractRevocationCertificates(lote, profile)
    }
    return certs.first { tc -> tc.providerName.any { it.value == provider } }.certificate!!
}

private val asitCert = certificateOf(pidLote, LoteProfile.PID, "A-SIT")
private val pidOnlyCert = certificateOf(pidLote, LoteProfile.PID, "PID Provider1")
private val wrpacOnlyCert = certificateOf(wrpacLote, LoteProfile.WRPAC, "Idakto")

private fun List<X509Certificate>.containsCert(cert: X509Certificate): Boolean {
    val der = cert.encodeToDer()
    return any { it.encodeToDer().contentEquals(der) }
}

private fun provider(
    lists: Collection<ListOfTrustedEntities> = listOf(pidLote, wrpacLote),
    trustListsFor: (suspend (String) -> Collection<ListOfTrustedEntities>)? = null,
    additionalAnchors: List<X509Certificate> = emptyList(),
) = trustListsFor?.let { LoTETrustAnchorProvider({ lists }, it, additionalAnchors) }
    ?: LoTETrustAnchorProvider(trustLists = { lists }, additionalAnchors = additionalAnchors)

val LoTETrustAnchorProviderTest by matrixSuite {


    "profileOf detects the list from its metadata" {
        filter.profileOf(pidLote) shouldBe LoteProfile.PID
        filter.profileOf(wrpacLote) shouldBe LoteProfile.WRPAC
    }

    "the detecting overload equals the explicit one" {
        filter.extractIssuanceCertificates(pidLote) shouldBe
                filter.extractIssuanceCertificates(pidLote, LoteProfile.PID)
        filter.extractRevocationCertificates(pidLote) shouldBe
                filter.extractRevocationCertificates(pidLote, LoteProfile.PID)
    }

    "the explicit overload rejects a list of another profile" {
        filter.extractIssuanceCertificates(pidLote, LoteProfile.WRPAC) shouldBe emptyList()
    }

    "a PID resolves to the PID list" {
        provider().issuanceAnchors("urn:eudi:pid:1") shouldBe issuanceCertsOf(pidLote, LoteProfile.PID)
    }

    "PID anchors contain the PID providers and nothing from the WRPAC list" {
        val anchors = provider().issuanceAnchors("urn:eudi:pid:1")
        anchors.containsCert(asitCert) shouldBe true
        anchors.containsCert(pidOnlyCert) shouldBe true
        anchors.containsCert(wrpacOnlyCert) shouldBe false
    }

    "the other PID prefix resolves to the same list" {
        provider().issuanceAnchors("eu.europa.ec.eudi.pid.1") shouldBe
                provider().issuanceAnchors("urn:eudi:pid:1")
    }

    "an unknown credential identifier maps to EAA, for which no list is configured" {
        provider().issuanceAnchors("urn:example:loyalty-card:1") shouldBe emptyList()
    }

    "a custom trustListsFor overrides the default mapping" {
        val custom = provider(trustListsFor = { listOf(wrpacLote) })
        val anchors = custom.issuanceAnchors("urn:eudi:pid:1")
        anchors.containsCert(wrpacOnlyCert) shouldBe true
        anchors.containsCert(asitCert) shouldBe false
    }

    "a trustListsFor returning nothing yields no anchors" {
        provider(trustListsFor = { emptyList() }).issuanceAnchors("urn:eudi:pid:1") shouldBe emptyList()
    }

    "the published list's only revocation service is dropped, because its O matches TETradeName, not TEName" {
        provider().revocationAnchors("urn:eudi:pid:1") shouldBe emptyList()
    }

    "the WRPAC list has no revocation services" {
        provider().revocationAnchors(LoteProfile.WRPAC) shouldBe emptyList()
    }

    "the profile overload selects that list" {
        provider().issuanceAnchors(LoteProfile.WRPAC) shouldBe issuanceCertsOf(wrpacLote, LoteProfile.WRPAC)
    }

    "the profile overload yields nothing when no such list is configured" {
        provider(lists = listOf(pidLote)).issuanceAnchors(LoteProfile.WRPAC) shouldBe emptyList()
        provider(lists = listOf(pidLote)).revocationAnchors(LoteProfile.WALLET) shouldBe emptyList()
    }

    "additional anchors are part of every result" {
        val p = provider(lists = emptyList(), additionalAnchors = listOf(asitCert))
        p.issuanceAnchors("urn:eudi:pid:1") shouldBe listOf(asitCert)
        p.revocationAnchors("urn:eudi:pid:1") shouldBe listOf(asitCert)
        p.issuanceAnchors(LoteProfile.PID) shouldBe listOf(asitCert)
        p.revocationAnchors(LoteProfile.PID) shouldBe listOf(asitCert)
    }

    "without lists and without additional anchors the result is empty" {
        provider(lists = emptyList()).issuanceAnchors("urn:eudi:pid:1") shouldBe emptyList()
    }
}