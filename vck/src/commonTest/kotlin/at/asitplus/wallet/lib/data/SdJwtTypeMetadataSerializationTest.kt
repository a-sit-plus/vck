package at.asitplus.wallet.lib.data

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

val SdJwtTypeMetadataSerializationTest by testSuite {

    "Deserialization is correct for EHIC" {
        val input = """{
          "vct": "urn:eudi:ehic:1",
          "name": "DC4EU EHIC SD-JWT VCTM",
          "description": "DC4EU European Health Insurance Card (EHIC) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single language tag (en-US).",
          "${'$'}comment": "Implementation of the DC4EU VCTM may require Member State-specific clarifications to align with national policies governing the display of included claims.",
          "display": [
            {
              "lang": "en-US",
              "name": "EHIC SD-JWT VC",
              "description": "European Health Insurance Card (EHIC) SD-JWT VC",
              "rendering": {
                "svg_templates": [
                  {
                    "uri": "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-svg-dc4eu-01.svg",
                    "uri#integrity": "sha256-GwKqaDcprF+QV3HPDQmbS/foYIErctFzieEicgvyRk4=",
                    "properties": {
                      "orientation": "landscape",
                      "color_scheme": "light",
                      "contrast": "normal"
                    }
                  }
                ]
              }
            }
          ],
          "claims": [
            {
              "path": [
                "personal_administrative_number"
              ],
              "sd": "always",
              "svg_id": "personal_administrative_number_6",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Social Security PIN",
                  "description": "Unique personal identifier used by social security services."
                }
              ]
            },
            {
              "path": [
                "issuing_authority"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Issuing authority"
                }
              ]
            },
            {
              "path": [
                "issuing_authority",
                "id"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Issuing authority id",
                  "description": "EHIC issuing authority unique identifier."
                }
              ]
            },
            {
              "path": [
                "issuing_authority",
                "name"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Issuing authority name",
                  "description": "EHIC issuing authority name."
                }
              ]
            },
            {
              "path": [
                "issuing_country"
              ],
              "sd": "never",
              "svg_id": "issuing_country_2",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Issuing country",
                  "description": "EHIC issuing country."
                }
              ]
            },
            {
              "path": [
                "date_of_expiry"
              ],
              "sd": "never",
              "svg_id": "date_of_expiry_9",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Expiry date",
                  "description": "EHIC expiration date."
                }
              ]
            },
            {
              "path": [
                "date_of_issuance"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Issue date",
                  "description": "EHIC validity start date."
                }
              ]
            },
            {
              "path": [
                "authentic_source"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Competent institution"
                }
              ]
            },
            {
              "path": [
                "authentic_source",
                "id"
              ],
              "sd": "never",
              "svg_id": "authentic_source_id_7a",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Competent institution id",
                  "description": "Identifier of the competent insitution as registered in the EESSI Institution Repository."
                }
              ]
            },
            {
              "path": [
                "authentic_source",
                "name"
              ],
              "sd": "never",
              "svg_id": "authentic_source_name_7b",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Competent institution name",
                  "description": "Name of the competent insitution as registered in the EESSI Institution Repository."
                }
              ]
            },
            {
              "path": [
                "ending_date"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Ending date",
                  "description": "End date of the insurance coverage."
                }
              ]
            },
            {
              "path": [
                "starting_date"
              ],
              "sd": "never",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Starting date",
                  "description": "Start date of the insurance coverage."
                }
              ]
            },
            {
              "path": [
                "document_number"
              ],
              "sd": "always",
              "svg_id": "document_number_8",
              "display": [
                {
                  "lang": "en-US",
                  "label": "Document number",
                  "description": "EHIC unique document identifier."
                }
              ]
            }
          ],
          "schema_uri": "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json",
          "schema_uri#integrity": "sha256-lNMpT2YzCPU1AuIpSIjryv6KUgBUBUVs3eNbZQoMJNA="
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(input).apply {
            verifiableCredentialType shouldBe "urn:eudi:ehic:1"
            name shouldBe "DC4EU EHIC SD-JWT VCTM"
            description shouldBe "DC4EU European Health Insurance Card (EHIC) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single language tag (en-US)."
            display.shouldNotBeNull().shouldBeSingleton().first().apply {
                language shouldBe "en-US"
                name shouldBe "EHIC SD-JWT VC"
                description shouldBe "European Health Insurance Card (EHIC) SD-JWT VC"
                rendering.shouldNotBeNull().svgTemplate.shouldNotBeNull().shouldBeSingleton().first().apply {
                    uri shouldBe "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-svg-dc4eu-01.svg"
                    uriIntegrity shouldBe "sha256-GwKqaDcprF+QV3HPDQmbS/foYIErctFzieEicgvyRk4="
                    properties.shouldNotBeNull().apply {
                        get("orientation") shouldBe "landscape"
                        get("color_scheme") shouldBe "light"
                        get("contrast") shouldBe "normal"
                    }
                }
            }
            claims.shouldNotBeNull().first { it.path.segments.firstNamedSegment() == "document_number" }.apply {
                path.segments.firstNamedSegment() shouldBe "document_number"
                selectivelyDisclosable shouldBe ClaimSelectiveDisclosable.ALWAYS
                svgId shouldBe "document_number_8"
                display.shouldNotBeNull().first().apply {
                    language shouldBe "en-US"
                    label shouldBe "Document number"
                    description shouldBe "EHIC unique document identifier."
                }
            }
            schemaUri shouldBe "https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-schema-dc4eu-01.json"
            schemaUriIntegrity shouldBe "sha256-lNMpT2YzCPU1AuIpSIjryv6KUgBUBUVs3eNbZQoMJNA="
        }
    }


    "Deserialization is correct for Sample" {
        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-example-2-type-metadata
        val input = """{
          "vct": "https://betelgeuse.example.com/education_credential",
          "name": "Betelgeuse Education Credential - Preliminary Version",
          "description": "This is our development version of the education credential. Don't panic.",
          "extends": "https://galaxy.example.com/galactic-education-credential-0.9",
          "extends#integrity": "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=",
          "display": [
            {
              "lang": "en-US",
              "name": "Betelgeuse Education Credential",
              "description": "An education credential for all carbon-based life forms on Betelgeusians",
              "rendering": {
                "simple": {
                  "logo": {
                    "uri": "https://betelgeuse.example.com/public/education-logo.png",
                    "uri#integrity": "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=",
                    "alt_text": "Betelgeuse Ministry of Education logo"
                  },
                  "background_color": "#12107c",
                  "text_color": "#FFFFFF"
                },
                "svg_templates": [
                  {
                    "uri": "https://betelgeuse.example.com/public/credential-english.svg",
                    "uri#integrity": "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=",
                    "properties": {
                      "orientation": "landscape",
                      "color_scheme": "light",
                      "contrast": "high"
                    }
                  }
                ]
              }
            },
            {
              "lang": "de-DE",
              "name": "Betelgeuse-Bildungsnachweis",
              "rendering": {
                "simple": {
                  "logo": {
                    "uri": "https://betelgeuse.example.com/public/education-logo-de.png",
                    "uri#integrity": "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=",
                    "alt_text": "Logo des Betelgeusischen Bildungsministeriums"
                  },
                  "background_color": "#12107c",
                  "text_color": "#FFFFFF"
                },
                "svg_templates": [
                  {
                    "uri": "https://betelgeuse.example.com/public/credential-german.svg",
                    "uri#integrity": "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=",
                    "properties": {
                      "orientation": "landscape",
                      "color_scheme": "light",
                      "contrast": "high"
                    }
                  }
                ]
              }
            }
          ],
          "claims": [
            {
              "path": ["name"],
              "display": [
                {
                  "lang": "de-DE",
                  "label": "Vor- und Nachname",
                  "description": "Der Name des Studenten"
                },
                {
                  "lang": "en-US",
                  "label": "Name",
                  "description": "The name of the student"
                }
              ],
              "sd": "allowed"
            },
            {
              "path": ["address"],
              "display": [
                {
                  "lang": "de-DE",
                  "label": "Adresse",
                  "description": "Adresse zum Zeitpunkt des Abschlusses"
                },
                {
                  "lang": "en-US",
                  "label": "Address",
                  "description": "Address at the time of graduation"
                }
              ],
              "sd": "always"
            },
            {
              "path": ["address", "street_address"],
              "display": [
                {
                  "lang": "de-DE",
                  "label": "Straße"
                },
                {
                  "lang": "en-US",
                  "label": "Street Address"
                }
              ],
              "sd": "always",
              "svg_id": "address_street_address"
            },
            {
              "path": ["degrees", null],
              "display": [
                {
                  "lang": "de-DE",
                  "label": "Abschluss",
                  "description": "Der Abschluss des Studenten"
                },
                {
                  "lang": "en-US",
                  "label": "Degree",
                  "description": "Degree earned by the student"
                }
              ],
              "sd": "allowed"
            }
          ],
          "schema_uri": "https://exampleuniversity.com/public/credential-schema-0.9",
          "schema_uri#integrity": "sha256-He4fNeA4xvjLbh/e+rd9Hw3l60OS4tEliHE7NDYXRwA="
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(input).apply {
            verifiableCredentialType shouldBe "https://betelgeuse.example.com/education_credential"
            name shouldBe "Betelgeuse Education Credential - Preliminary Version"
            description shouldBe "This is our development version of the education credential. Don't panic."
            extends shouldBe "https://galaxy.example.com/galactic-education-credential-0.9"
            extendsIntegrity shouldBe "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU="
            display.shouldNotBeNull().first { it.language == "en-US" }.apply {
                name shouldBe "Betelgeuse Education Credential"
                description shouldBe "An education credential for all carbon-based life forms on Betelgeusians"
                rendering.shouldNotBeNull().simple.shouldNotBeNull().apply {
                    logo.shouldNotBeNull().apply {
                        uri shouldBe "https://betelgeuse.example.com/public/education-logo.png"
                        uriIntegrity shouldBe "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U="
                        altText shouldBe "Betelgeuse Ministry of Education logo"
                    }
                    backgroundColor shouldBe "#12107c"
                    textColor shouldBe "#FFFFFF"
                }
                rendering.shouldNotBeNull().svgTemplate.shouldNotBeNull().shouldBeSingleton().first().apply {
                    uri shouldBe "https://betelgeuse.example.com/public/credential-english.svg"
                    uriIntegrity shouldBe "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4="
                    properties.shouldNotBeNull().apply {
                        get("orientation") shouldBe "landscape"
                        get("color_scheme") shouldBe "light"
                        get("contrast") shouldBe "high"
                    }
                }
            }
            display.shouldNotBeNull().first { it.language == "de-DE" }.apply {
                name shouldBe "Betelgeuse-Bildungsnachweis"
                description.shouldBeNull()
            }
            claims.shouldNotBeNull().first { it.path.segments.firstNamedSegment() == "name" }.apply {
                selectivelyDisclosable shouldBe ClaimSelectiveDisclosable.ALLOWED
                display.shouldNotBeNull().first { it.language == "en-US" }.apply {
                    label shouldBe "Name"
                    description shouldBe "The name of the student"
                }
                display.shouldNotBeNull().first { it.language == "de-DE" }.apply {
                    label shouldBe "Vor- und Nachname"
                    description shouldBe "Der Name des Studenten"
                }
            }
            schemaUri shouldBe "https://exampleuniversity.com/public/credential-schema-0.9"
            schemaUriIntegrity shouldBe "sha256-He4fNeA4xvjLbh/e+rd9Hw3l60OS4tEliHE7NDYXRwA="
        }
    }
}
private fun NonEmptyList<DCQLClaimsPathPointerSegment>.firstNamedSegment(): String? =
    filterIsInstance<DCQLClaimsPathPointerSegment.NameSegment>().map { it.name }.firstOrNull()