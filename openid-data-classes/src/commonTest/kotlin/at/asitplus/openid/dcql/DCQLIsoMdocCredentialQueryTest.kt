package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val DCQLIsoMdocCredentialQueryTest by testSuite {
    "serialization" {
        val value = DCQLIsoMdocCredentialQuery(
            id = DCQLCredentialQueryIdentifier("test"),
            format = CredentialFormatEnum.MSO_MDOC,
            meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "test"
            ),
        )

        val base: DCQLCredentialQuery = value
        val serialized = Json.encodeToJsonElement(base)
        serialized shouldBe Json.encodeToJsonElement(value)
        serialized.jsonObject.entries shouldHaveSize 3

        DCQLCredentialQuery.SerialNames.ID shouldBeIn serialized.jsonObject.keys
        DCQLCredentialQuery.SerialNames.FORMAT shouldBeIn serialized.jsonObject.keys
    }
}