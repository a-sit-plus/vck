package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

val DCQLCredentialQueryTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLCredentialQuery.SerialNames.ID shouldBe "id"
            DCQLCredentialQuery.SerialNames.FORMAT shouldBe "format"
            DCQLCredentialQuery.SerialNames.META shouldBe "meta"
            DCQLCredentialQuery.SerialNames.CLAIM_SETS shouldBe "claim_sets"
            DCQLCredentialQuery.SerialNames.CLAIMS shouldBe "claims"
        }
    }
    "serialization" {
        val value = DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(
                Random.nextBytes(32).encodeToString(Base64UrlStrict)
            ),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(null)
                )
            ),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("mustmatch")
            )
        )

        val expectedJsonObject = buildJsonObject {
            put(DCQLCredentialQuery.SerialNames.ID, JsonPrimitive(value.id.string))
            put(DCQLCredentialQuery.SerialNames.META, JsonPrimitive(value.id.string))
            put(
                DCQLCredentialQuery.SerialNames.FORMAT,
                JsonPrimitive(CredentialFormatEnum.DC_SD_JWT.text)
            )
            put(
                DCQLCredentialQuery.SerialNames.META,
                buildJsonObject {
                    put(
                        DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES,
                        buildJsonArray {
                            add("mustmatch")
                        }
                    )
                }
            )
            put(DCQLCredentialQuery.SerialNames.CLAIMS, buildJsonArray {
                add(buildJsonObject {
                    put(DCQLJsonClaimsQuery.SerialNames.PATH, buildJsonArray {
                        add(JsonNull)
                    })
                })
            })
        }

        Json.encodeToJsonElement(value) shouldBe expectedJsonObject
        Json.decodeFromJsonElement<DCQLCredentialQuery>(expectedJsonObject) shouldBe value
    }
}