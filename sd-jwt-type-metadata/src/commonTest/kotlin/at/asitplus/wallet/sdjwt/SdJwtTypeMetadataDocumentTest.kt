package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

private val BETELGEUSE_V42_JSON =
    """{"vct":"https://betelgeuse.example.com/education_credential/v42","name":"Betelgeuse Education Credential - First Version","description":"This is our first version of the education credential. Don't panic.","display":[{"locale":"en-US","name":"Betelgeuse Education Credential","description":"An education credential for all carbon-based life forms on Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Betelgeuse Ministry of Education logo"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background.png","uri#integrity":"sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-english.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}},{"locale":"de-DE","name":"Betelgeuse-Bildungsnachweis","description":"Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo-de.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Logo des Betelgeusischen Bildungsministeriums"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background-de.png","uri#integrity":"sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfg=="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-german.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}}],"claims":[{"path":["name"],"display":[{"locale":"de-DE","label":"Vor- und Nachname","description":"Der Name des/der Studierenden"},{"locale":"en-US","label":"Name","description":"The name of the student"}],"sd":"always","mandatory":true},{"path":["address"],"display":[{"locale":"de-DE","label":"Adresse","description":"Adresse zum Zeitpunkt des Abschlusses"},{"locale":"en-US","label":"Address","description":"Address at the time of graduation"}],"sd":"always"},{"path":["address","street_address"],"display":[{"locale":"de-DE","label":"Straße"},{"locale":"en-US","label":"Street Address"}],"sd":"always","svg_id":"address_street_address"},{"path":["degrees"],"display":[{"locale":"de-DE","label":"Abschlüsse","description":"Abschlüsse des/der Studierenden"},{"locale":"en-US","label":"Degrees","description":"Degrees earned by the student"}],"sd":"never"},{"path":["degrees",null],"sd":"always"},{"path":["degrees",null,"field_of_study"],"display":[{"locale":"de-DE","label":"Studienfach"},{"locale":"en-US","label":"Field of Study"}],"sd":"never"},{"path":["degrees",null,"date_awarded"],"display":[{"locale":"de-DE","label":"Verleihungsdatum"},{"locale":"en-US","label":"Date Awarded"}],"sd":"always"}]}"""

@Suppress("unused")
val SdJwtTypeMetadataDocumentTest by matrixSuite {
    testSuite("reserializing json elements preserves string character order") {
        listOf(
            BETELGEUSE_V42_JSON,
            """{"name":"Betelgeuse Education Credential - First Version","vct":"https://betelgeuse.example.com/education_credential/v42","description":"This is our first version of the education credential. Don't panic.","display":[{"locale":"en-US","name":"Betelgeuse Education Credential","description":"An education credential for all carbon-based life forms on Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Betelgeuse Ministry of Education logo"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background.png","uri#integrity":"sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-english.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}},{"locale":"de-DE","name":"Betelgeuse-Bildungsnachweis","description":"Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo-de.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Logo des Betelgeusischen Bildungsministeriums"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background-de.png","uri#integrity":"sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfg=="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-german.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}}],"claims":[{"path":["name"],"display":[{"locale":"de-DE","label":"Vor- und Nachname","description":"Der Name des/der Studierenden"},{"locale":"en-US","label":"Name","description":"The name of the student"}],"sd":"always","mandatory":true},{"path":["address"],"display":[{"locale":"de-DE","label":"Adresse","description":"Adresse zum Zeitpunkt des Abschlusses"},{"locale":"en-US","label":"Address","description":"Address at the time of graduation"}],"sd":"always"},{"path":["address","street_address"],"display":[{"locale":"de-DE","label":"Straße"},{"locale":"en-US","label":"Street Address"}],"sd":"always","svg_id":"address_street_address"},{"path":["degrees"],"display":[{"locale":"de-DE","label":"Abschlüsse","description":"Abschlüsse des/der Studierenden"},{"locale":"en-US","label":"Degrees","description":"Degrees earned by the student"}],"sd":"never"},{"path":["degrees",null],"sd":"always"},{"path":["degrees",null,"field_of_study"],"display":[{"locale":"de-DE","label":"Studienfach"},{"locale":"en-US","label":"Field of Study"}],"sd":"never"},{"path":["degrees",null,"date_awarded"],"display":[{"locale":"de-DE","label":"Verleihungsdatum"},{"locale":"en-US","label":"Date Awarded"}],"sd":"always"}]}""",
            """{"vct":"urn:eudi:ehic:1","name":"DC4EU EHIC SD-JWT VCTM","description":"DC4EU European Health Insurance Card (EHIC) SD-JWT Verifiable Credential Type Metadata, based on ietf-oauth-sd-jwt-vc (draft 09), using a single localeuage tag (en-US).","display":[{"locale":"en-US","name":"EHIC SD-JWT VC","description":"European Health Insurance Card (EHIC) SD-JWT VC","rendering":{"svg_templates":[{"uri":"https://demo-issuer.wwwallet.org/public/creds/ehic/european-health-insurance-card-svg-dc4eu-01.svg","uri#integrity":"sha256-GwKqaDcprF+QV3HPDQmbS/foYIErctFzieEicgvyRk4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"normal"}}]}}],"claims":[{"path":["personal_administrative_number"],"sd":"always","svg_id":"personal_administrative_number_6","display":[{"locale":"en-US","label":"Social Security PIN","description":"Unique personal identifier used by social security services."}]},{"path":["issuing_authority"],"sd":"never","display":[{"locale":"en-US","label":"Issuing authority"}]},{"path":["issuing_authority","id"],"sd":"never","display":[{"locale":"en-US","label":"Issuing authority id","description":"EHIC issuing authority unique identifier."}]},{"path":["issuing_authority","name"],"sd":"never","display":[{"locale":"en-US","label":"Issuing authority name","description":"EHIC issuing authority name."}]},{"path":["issuing_country"],"sd":"never","svg_id":"issuing_country_2","display":[{"locale":"en-US","label":"Issuing country","description":"EHIC issuing country."}]},{"path":["date_of_expiry"],"sd":"never","svg_id":"date_of_expiry_9","display":[{"locale":"en-US","label":"Expiry date","description":"EHIC expiration date."}]},{"path":["date_of_issuance"],"sd":"never","display":[{"locale":"en-US","label":"Issue date","description":"EHIC validity start date."}]},{"path":["authentic_source"],"sd":"never","display":[{"locale":"en-US","label":"Competent institution"}]},{"path":["authentic_source","id"],"sd":"never","svg_id":"authentic_source_id_7a","display":[{"locale":"en-US","label":"Competent institution id","description":"Identifier of the competent insitution as registered in the EESSI Institution Repository."}]},{"path":["authentic_source","name"],"sd":"never","svg_id":"authentic_source_name_7b","display":[{"locale":"en-US","label":"Competent institution name","description":"Name of the competent insitution as registered in the EESSI Institution Repository."}]},{"path":["ending_date"],"sd":"never","display":[{"locale":"en-US","label":"Ending date","description":"End date of the insurance coverage."}]},{"path":["starting_date"],"sd":"never","display":[{"locale":"en-US","label":"Starting date","description":"Start date of the insurance coverage."}]},{"path":["document_number"],"sd":"always","svg_id":"document_number_8","display":[{"locale":"en-US","label":"Document number","description":"EHIC unique document identifier."}]}]}""",
            """{"vct":"https://betelgeuse.example.com/education_credential","name":"Betelgeuse Education Credential - Preliminary Version","description":"This is our development version of the education credential. Don't panic.","extends":"https://galaxy.example.com/galactic-education-credential-0.9","extends#integrity":"sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=","display":[{"locale":"en-US","name":"Betelgeuse Education Credential","description":"An education credential for all carbon-based life forms on Betelgeusians","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Betelgeuse Ministry of Education logo"},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-english.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}},{"locale":"de-DE","name":"Betelgeuse-Bildungsnachweis","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo-de.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Logo des Betelgeusischen Bildungsministeriums"},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-german.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}}],"claims":[{"path":["name"],"display":[{"locale":"de-DE","label":"Vor- und Nachname","description":"Der Name des Studenten"},{"locale":"en-US","label":"Name","description":"The name of the student"}],"sd":"allowed"},{"path":["address"],"display":[{"locale":"de-DE","label":"Adresse","description":"Adresse zum Zeitpunkt des Abschlusses"},{"locale":"en-US","label":"Address","description":"Address at the time of graduation"}],"sd":"always"},{"path":["address","street_address"],"display":[{"locale":"de-DE","label":"Straße"},{"locale":"en-US","label":"Street Address"}],"sd":"always","svg_id":"address_street_address"},{"path":["degrees",null],"display":[{"locale":"de-DE","label":"Abschluss","description":"Der Abschluss des Studenten"},{"locale":"en-US","label":"Degree","description":"Degree earned by the student"}],"sd":"allowed"}],"schema_uri":"https://exampleuniversity.com/public/credential-schema-0.9","schema_uri#integrity":"sha256-He4fNeA4xvjLbh/e+rd9Hw3l60OS4tEliHE7NDYXRwA="}""",
        ).asData() test { json ->
            val document = Json.Default.decodeFromString(SdJwtTypeMetadataDocument.serializer(), json)
            document.originalBytes.decodeToString() shouldBe json
        }
    }

    test("parsed content of Betelgeuse education credential v42") {
        val document = Json.Default.decodeFromString(SdJwtTypeMetadataDocument.serializer(), BETELGEUSE_V42_JSON)
        document.originalBytes.decodeToString() shouldBe BETELGEUSE_V42_JSON

        val definition = document.definition
        definition.vct shouldBe SdJwtVcType("https://betelgeuse.example.com/education_credential/v42")
        definition.name shouldBe "Betelgeuse Education Credential - First Version"
        definition.description shouldBe "This is our first version of the education credential. Don't panic."
        definition.extends shouldBe null
        definition.extendsIntegrity shouldBe null

        val typeDisplay = definition.display.shouldNotBeNull().toList()
        typeDisplay.size shouldBe 2

        typeDisplay.first { it.locale == Rfc5646LanguageTag("en-US") }.apply {
            name shouldBe "Betelgeuse Education Credential"
            description shouldBe "An education credential for all carbon-based life forms on Betelgeuse."
            rendering.shouldNotBeNull().apply {
                simple.shouldNotBeNull().apply {
                    logo.shouldNotBeNull().apply {
                        uri.string shouldBe "https://betelgeuse.example.com/public/education-logo.png"
                        uriIntegrity.toString() shouldBe "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U="
                        alternativeText shouldBe "Betelgeuse Ministry of Education logo"
                    }
                    backgroundImage.shouldNotBeNull().apply {
                        uri.string shouldBe "https://betelgeuse.example.com/public/credential-background.png"
                        uriIntegrity.toString() shouldBe "sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="
                    }
                    backgroundColor.shouldNotBeNull().string shouldBe "#12107c"
                    textColor.shouldNotBeNull().string shouldBe "#FFFFFF"
                }
                svgTemplates.shouldNotBeNull().single().apply {
                    uri.string shouldBe "https://betelgeuse.example.com/public/credential-english.svg"
                    uriIntegrity.toString() shouldBe "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4="
                    properties.shouldNotBeNull().apply {
                        imageOrientation shouldBe SvgTemplatePropertyImageOrientation.landscape
                        colorScheme shouldBe SvgTemplatePropertyColorScheme.light
                        contrast shouldBe SvgTemplatePropertyContrast.high
                    }
                }
            }
        }

        typeDisplay.first { it.locale == Rfc5646LanguageTag("de-DE") }.apply {
            name shouldBe "Betelgeuse-Bildungsnachweis"
            description shouldBe "Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse."
            rendering.shouldNotBeNull().apply {
                simple.shouldNotBeNull().logo.shouldNotBeNull().alternativeText shouldBe "Logo des Betelgeusischen Bildungsministeriums"
                svgTemplates.shouldNotBeNull()
                    .single().uri.string shouldBe "https://betelgeuse.example.com/public/credential-german.svg"
            }
        }

        val claims = definition.claims.shouldNotBeNull().toList()
        claims.size shouldBe 7

        claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("name") }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            isMandatory shouldBe true
            display.shouldNotBeNull().apply {
                first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Name"
                first { it.locale == Rfc5646LanguageTag("en-US") }.description shouldBe "The name of the student"
                first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Vor- und Nachname"
                first { it.locale == Rfc5646LanguageTag("de-DE") }.description shouldBe "Der Name des/der Studierenden"
            }
        }

        claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("address") }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            isMandatory shouldBe null
            svgId shouldBe null
            display.shouldNotBeNull().apply {
                first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Address"
                first { it.locale == Rfc5646LanguageTag("de-DE") }.description shouldBe "Adresse zum Zeitpunkt des Abschlusses"
            }
        }

        claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("address", "street_address") }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            svgId shouldBe SvgContentPlaceholder("address_street_address")
            display.shouldNotBeNull().first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Straße"
        }

        claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("degrees") }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.NEVER
            display.shouldNotBeNull().first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Degrees"
        }

        val degreesWildcardPath = SdJwtTypeMetadataClaimInformationPath("degrees") + null
        claims.first { it.path == degreesWildcardPath }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            isMandatory shouldBe null
            display shouldBe null
        }

        claims.first { it.path == degreesWildcardPath + "field_of_study" }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.NEVER
            display.shouldNotBeNull().apply {
                first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Studienfach"
                first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Field of Study"
            }
        }

        claims.first { it.path == degreesWildcardPath + "date_awarded" }.apply {
            selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            display.shouldNotBeNull().apply {
                first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Verleihungsdatum"
                first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Date Awarded"
            }
        }
    }
}
