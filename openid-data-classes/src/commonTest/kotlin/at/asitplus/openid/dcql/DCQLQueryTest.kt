package at.asitplus.openid.dcql

import at.asitplus.data.collections.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.random.Random

class DCQLQueryTest : FreeSpec({
    "specification" - {
        "serial names" {
            DCQLQuery.SerialNames.CREDENTIALS shouldBe "credentials"
            DCQLQuery.SerialNames.CREDENTIAL_SETS shouldBe "credential_sets"
        }
    }
    "instance serialization" {
        val queryId1 = DCQLCredentialQueryIdentifier(
            Random.Default.nextBytes(32).encodeToString(Base64UrlStrict)
        )
        val serialized = Json.encodeToJsonElement(
            DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLCredentialQueryInstance(
                        id = queryId1,
                        format = CredentialFormatEnum.MSO_MDOC,
                    )
                ),
                credentialSets = nonEmptyListOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(listOf(queryId1))
                    )
                ),
            )
        ).jsonObject

        DCQLQuery.SerialNames.CREDENTIALS shouldBeIn serialized.keys
        DCQLQuery.SerialNames.CREDENTIAL_SETS shouldBeIn serialized.keys
    }
})