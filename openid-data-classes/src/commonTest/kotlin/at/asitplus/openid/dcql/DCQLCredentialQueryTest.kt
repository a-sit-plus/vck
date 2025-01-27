package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

class DCQLCredentialQueryTest : FreeSpec({
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
        val value = DCQLCredentialQueryInstance(
            id = DCQLCredentialQueryIdentifier(
                Random.nextBytes(32).encodeToString(Base64UrlStrict)
            ),
            format = CredentialFormatEnum.VC_SD_JWT,
            claims = DCQLClaimsQueryList(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(null)
                )
            )
        )

        val expectedJsonObject = buildJsonObject {
            put(DCQLCredentialQuery.SerialNames.ID, JsonPrimitive(value.id.string))
            put(
                DCQLCredentialQuery.SerialNames.FORMAT,
                JsonPrimitive(CredentialFormatEnum.VC_SD_JWT.text)
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
        Json.decodeFromJsonElement<DCQLCredentialQueryInstance>(expectedJsonObject) shouldBe value
    }
})