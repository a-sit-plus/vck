package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentName
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegment
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocument
import at.asitplus.wallet.sdjwt.SelectiveDisclosureConstraints
import at.asitplus.wallet.sdjwt.SvgTemplatePropertyColorScheme
import at.asitplus.wallet.sdjwt.SvgTemplatePropertyContrast
import at.asitplus.wallet.sdjwt.SvgTemplatePropertyImageOrientation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SdJwtTypeMetadataDocumentSerializationTest by testSuite {
    "Deserialization is correct for EHIC" {
        val input = """{
          "vct": "urn:eudi:ehic:1",
          "name": "DC4EU EHIC SD-JWT VCTM",
          "description": "DC4EU European Health Insurance Card (EHIC) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single localeuage tag (en-US).",
          "display": [
            {
              "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
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
                  "locale": "en-US",
                  "label": "Document number",
                  "description": "EHIC unique document identifier."
                }
              ]
            }
          ]
        }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString(
            SdJwtTypeMetadataDocument.serializer(),
            input
        ).definition.toSdJwtTypeMetadata().toCredentialScheme().apply {
            CredentialRepresentation.SD_JWT shouldBeIn supportedRepresentations
            sdJwtType shouldBe "urn:eudi:ehic:1"
            claimDescriptions shouldHaveSize 13
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
              "locale": "en-US",
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
              "locale": "de-DE",
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
                  "locale": "de-DE",
                  "label": "Vor- und Nachname",
                  "description": "Der Name des Studenten"
                },
                {
                  "locale": "en-US",
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
                  "locale": "de-DE",
                  "label": "Adresse",
                  "description": "Adresse zum Zeitpunkt des Abschlusses"
                },
                {
                  "locale": "en-US",
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
                  "locale": "de-DE",
                  "label": "Straße"
                },
                {
                  "locale": "en-US",
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
                  "locale": "de-DE",
                  "label": "Abschluss",
                  "description": "Der Abschluss des Studenten"
                },
                {
                  "locale": "en-US",
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

        joseCompliantSerializer.decodeFromString<SdJwtTypeMetadataDocument>(input).definition.apply {
            vct.string shouldBe "https://betelgeuse.example.com/education_credential"
            name shouldBe "Betelgeuse Education Credential - Preliminary Version"
            description shouldBe "This is our development version of the education credential. Don't panic."
            extends?.string shouldBe "https://galaxy.example.com/galactic-education-credential-0.9"
            extendsIntegrity?.string shouldBe "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU="
            display.shouldNotBeNull().first { it.locale.string == "en-US" }.apply {
                name shouldBe "Betelgeuse Education Credential"
                description shouldBe "An education credential for all carbon-based life forms on Betelgeusians"
                rendering.shouldNotBeNull().simple.shouldNotBeNull().apply {
                    logo.shouldNotBeNull().apply {
                        uri.string shouldBe "https://betelgeuse.example.com/public/education-logo.png"
                        uriIntegrity?.string shouldBe "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U="
                        alternativeText shouldBe "Betelgeuse Ministry of Education logo"
                    }
                    backgroundColor?.string shouldBe "#12107c"
                    textColor?.string shouldBe "#FFFFFF"
                }
                rendering.shouldNotBeNull().svgTemplates.shouldNotBeNull().shouldBeSingleton().first().apply {
                    uri.string shouldBe "https://betelgeuse.example.com/public/credential-english.svg"
                    uriIntegrity?.string shouldBe "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4="
                    properties.shouldNotBeNull().apply {
                        imageOrientation shouldBe SvgTemplatePropertyImageOrientation.landscape
                        colorScheme shouldBe SvgTemplatePropertyColorScheme.light
                        contrast shouldBe SvgTemplatePropertyContrast.high
                    }
                }
            }
            display.shouldNotBeNull().first { it.locale.string == "de-DE" }.apply {
                name shouldBe "Betelgeuse-Bildungsnachweis"
                description.shouldBeNull()
            }
            claims.shouldNotBeNull().first { it.path.firstNamedSegment() == "name" }.apply {
                selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALLOWED
                display.shouldNotBeNull().first { it.locale.string == "en-US" }.apply {
                    label shouldBe "Name"
                    description shouldBe "The name of the student"
                }
                display.shouldNotBeNull().first { it.locale.string == "de-DE" }.apply {
                    label shouldBe "Vor- und Nachname"
                    description shouldBe "Der Name des Studenten"
                }
            }
        }
    }
}

private fun List<SdJwtTypeMetadataClaimInformationPathSegment?>.firstNamedSegment(): String? =
    filterIsInstance<SdJwtTypeMetadataClaimInformationPathSegmentName>().map { it.string }.firstOrNull()