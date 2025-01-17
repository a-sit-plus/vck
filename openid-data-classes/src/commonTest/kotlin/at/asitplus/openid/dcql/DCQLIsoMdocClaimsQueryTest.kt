package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.encodeBase64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

class DCQLIsoMdocClaimsQueryTest : FreeSpec({
    "specification" - {
        "serial names" {
            DCQLJsonClaimsQuery.SerialNames.PATH shouldBe "path"
        }
    }
    "instance serialization" - {
        val id = DCQLClaimsQueryIdentifier(Random.Default.nextBytes(32).encodeToString(Base64UrlStrict))
        val values = listOf<DCQLExpectedClaimValue>(
            DCQLExpectedClaimValue.DCQLExpectedClaimStringValue("test")
        )
        val namespace = Random.Default.nextBytes(32).encodeBase64()
        val claimName = Random.Default.nextBytes(32).encodeBase64()

        val value = DCQLIsoMdocClaimsQuery(
            id = id,
            namespace = namespace,
            claimName = claimName,
            values = values,
        )

        val correspondingJsonElement = buildJsonObject {
            put(DCQLClaimsQuery.SerialNames.ID, JsonPrimitive(id.string))
            put(DCQLClaimsQuery.SerialNames.VALUES, Json.encodeToJsonElement(values))
            put(DCQLIsoMdocClaimsQuery.SerialNames.CLAIM_NAME, JsonPrimitive(claimName))
            put(DCQLIsoMdocClaimsQuery.SerialNames.NAMESPACE, JsonPrimitive(namespace))
        }

        val base: DCQLClaimsQuery = value
        val serialized = Json.encodeToJsonElement(base)

        serialized shouldBe correspondingJsonElement
        Json.decodeFromJsonElement<DCQLClaimsQuery>(correspondingJsonElement) shouldBe base
    }

    "execution" {
        val credential = mapOf(
            "testNamespace" to mapOf(
                "testClaimName" to 0,
                "otherClaimName" to -1,
            ),
            "otherNamespace" to mapOf(
                "testClaimName" to -1,
                "otherClaimName" to -1
            )
        )


        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            namespace = "testNamespace",
            claimName = "testClaimName",
            values = listOf(
                DCQLExpectedClaimValue.DCQLExpectedClaimStringValue("test"),
                DCQLExpectedClaimValue.DCQLExpectedClaimIntegerValue(0),
                DCQLExpectedClaimValue.DCQLExpectedClaimBooleanValue(true),
            )
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocDCQLCredentialClaimStructure(it)
            },
            credentialQuery = DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.MSO_MDOC,
            )
        ).getOrThrow().shouldBeInstanceOf<DCQLClaimsQueryResult.IsoMdocClaimsQueryResult>().let {
            it.claimValue shouldBe 0
        }

        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            namespace = "testNamespace",
            claimName = "testClaimName",
            values = listOf(
                DCQLExpectedClaimValue.DCQLExpectedClaimStringValue("test"),
                DCQLExpectedClaimValue.DCQLExpectedClaimIntegerValue(-1),
                DCQLExpectedClaimValue.DCQLExpectedClaimBooleanValue(true),
            )
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocDCQLCredentialClaimStructure(it)
            },
            credentialQuery = DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.MSO_MDOC,
            )
        ).isSuccess shouldBe false

        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            values = listOf(
                DCQLExpectedClaimValue.DCQLExpectedClaimStringValue("test"),
                DCQLExpectedClaimValue.DCQLExpectedClaimIntegerValue(0),
                DCQLExpectedClaimValue.DCQLExpectedClaimBooleanValue(true),
            ),
            namespace = "testNamespace",
            claimName = "testClaimName",
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocDCQLCredentialClaimStructure(it)
            },
            credentialQuery = DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.VC_SD_JWT,
            )
        ).isSuccess shouldBe false
    }
})

