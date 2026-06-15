package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

@Suppress("unused")
val SdJwtTypeMetadataTest by testSuite {
    testSuite("claims") {
        withData(
            """{"vct":"https://betelgeuse.example.com/education_credential/v42","name":"Betelgeuse Education Credential - First Version","description":"This is our first version of the education credential. Don't panic.","display":[{"locale":"en-US","name":"Betelgeuse Education Credential","description":"An education credential for all carbon-based life forms on Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Betelgeuse Ministry of Education logo"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background.png","uri#integrity":"sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-english.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}},{"locale":"de-DE","name":"Betelgeuse-Bildungsnachweis","description":"Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse.","rendering":{"simple":{"logo":{"uri":"https://betelgeuse.example.com/public/education-logo-de.png","uri#integrity":"sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=","alt_text":"Logo des Betelgeusischen Bildungsministeriums"},"background_image":{"uri":"https://betelgeuse.example.com/public/credential-background-de.png","uri#integrity":"sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfg=="},"background_color":"#12107c","text_color":"#FFFFFF"},"svg_templates":[{"uri":"https://betelgeuse.example.com/public/credential-german.svg","uri#integrity":"sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=","properties":{"orientation":"landscape","color_scheme":"light","contrast":"high"}}]}}],"claims":[{"path":["name"],"display":[{"locale":"de-DE","label":"Vor- und Nachname","description":"Der Name des/der Studierenden"},{"locale":"en-US","label":"Name","description":"The name of the student"}],"sd":"always","mandatory":true},{"path":["address"],"display":[{"locale":"de-DE","label":"Adresse","description":"Adresse zum Zeitpunkt des Abschlusses"},{"locale":"en-US","label":"Address","description":"Address at the time of graduation"}],"sd":"always"},{"path":["address","street_address"],"display":[{"locale":"de-DE","label":"Straße"},{"locale":"en-US","label":"Street Address"}],"sd":"always","svg_id":"address_street_address"},{"path":["degrees"],"display":[{"locale":"de-DE","label":"Abschlüsse","description":"Abschlüsse des/der Studierenden"},{"locale":"en-US","label":"Degrees","description":"Degrees earned by the student"}],"sd":"never"},{"path":["degrees",null],"sd":"always"},{"path":["degrees",null,"field_of_study"],"display":[{"locale":"de-DE","label":"Studienfach"},{"locale":"en-US","label":"Field of Study"}],"sd":"never"},{"path":["degrees",null,"date_awarded"],"display":[{"locale":"de-DE","label":"Verleihungsdatum"},{"locale":"en-US","label":"Date Awarded"}],"sd":"always"}]}"""
        ) {
            val metadata = Json.decodeFromString<SdJwtTypeMetadata>(it)

            metadata.vct shouldBe SdJwtVcType("https://betelgeuse.example.com/education_credential/v42")
            metadata.name shouldBe "Betelgeuse Education Credential - First Version"
            metadata.description shouldBe "This is our first version of the education credential. Don't panic."

            val display = metadata.display!!.toList()
            display.size shouldBe 2

            val enDisplay = display.first { it.locale == Rfc5646LanguageTag("en-US") }
            enDisplay.name shouldBe "Betelgeuse Education Credential"
            enDisplay.description shouldBe "An education credential for all carbon-based life forms on Betelgeuse."
            val enSimple = enDisplay.rendering!!.simple!!
            enSimple.logo!!.uri.string shouldBe "https://betelgeuse.example.com/public/education-logo.png"
            enSimple.logo!!.uriIntegrity.toString() shouldBe "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U="
            enSimple.logo!!.alternativeText shouldBe "Betelgeuse Ministry of Education logo"
            enSimple.backgroundImage!!.uri.string shouldBe "https://betelgeuse.example.com/public/credential-background.png"
            enSimple.backgroundImage!!.uriIntegrity.toString() shouldBe "sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="
            enSimple.backgroundColor!!.string shouldBe "#12107c"
            enSimple.textColor!!.string shouldBe "#FFFFFF"
            val enSvg = enDisplay.rendering!!.svgTemplates!!.single()
            enSvg.uri.string shouldBe "https://betelgeuse.example.com/public/credential-english.svg"
            enSvg.uriIntegrity.toString() shouldBe "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4="
            enSvg.properties!!.imageOrientation shouldBe SvgTemplatePropertyImageOrientation.landscape
            enSvg.properties!!.colorScheme shouldBe SvgTemplatePropertyColorScheme.light
            enSvg.properties!!.contrast shouldBe SvgTemplatePropertyContrast.high

            val deDisplay = display.first { it.locale == Rfc5646LanguageTag("de-DE") }
            deDisplay.name shouldBe "Betelgeuse-Bildungsnachweis"
            deDisplay.description shouldBe "Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse."
            deDisplay.rendering!!.simple!!.logo!!.alternativeText shouldBe "Logo des Betelgeusischen Bildungsministeriums"
            deDisplay.rendering!!.svgTemplates!!.single().uri.string shouldBe "https://betelgeuse.example.com/public/credential-german.svg"

            val claims = metadata.claims!!.toList()
            claims.size shouldBe 7

            val nameClaim = claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("name") }
            nameClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            nameClaim.isMandatory shouldBe true
            nameClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Name"
            nameClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.description shouldBe "The name of the student"
            nameClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Vor- und Nachname"
            nameClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.description shouldBe "Der Name des/der Studierenden"

            val addressClaim = claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("address") }
            addressClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            addressClaim.isMandatory shouldBe null
            addressClaim.svgId shouldBe null
            addressClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Address"
            addressClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.description shouldBe "Adresse zum Zeitpunkt des Abschlusses"

            val streetClaim = claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("address", "street_address") }
            streetClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            streetClaim.svgId shouldBe SvgContentPlaceholder("address_street_address")
            streetClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Straße"
            streetClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Street Address"

            val degreesClaim = claims.first { it.path == SdJwtTypeMetadataClaimInformationPath("degrees") }
            degreesClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.NEVER
            degreesClaim.isMandatory shouldBe null
            degreesClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Degrees"
            degreesClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.description shouldBe "Abschlüsse des/der Studierenden"

            val degreesWildcardPath = SdJwtTypeMetadataClaimInformationPath("degrees") + null
            val degreesWildcardClaim = claims.first { it.path == degreesWildcardPath }
            degreesWildcardClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            degreesWildcardClaim.isMandatory shouldBe null
            degreesWildcardClaim.display shouldBe null

            val fieldOfStudyClaim = claims.first { it.path == degreesWildcardPath + "field_of_study" }
            fieldOfStudyClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.NEVER
            fieldOfStudyClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Studienfach"
            fieldOfStudyClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Field of Study"

            val dateAwardedClaim = claims.first { it.path == degreesWildcardPath + "date_awarded" }
            dateAwardedClaim.selectiveDisclosureConstraints shouldBe SelectiveDisclosureConstraints.ALWAYS
            dateAwardedClaim.display!!.first { it.locale == Rfc5646LanguageTag("de-DE") }.label shouldBe "Verleihungsdatum"
            dateAwardedClaim.display!!.first { it.locale == Rfc5646LanguageTag("en-US") }.label shouldBe "Date Awarded"
        }
    }
}
