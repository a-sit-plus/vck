package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.io.encoding.Base64
import kotlin.random.Random

val DCQLIsoMdocClaimsQueryTest by matrixSuite {
    "specification" - {
        "serial names" {
            DCQLClaimsQuery.SerialNames.PATH shouldBe "path"
        }
    }
    "instance serialization" {
        val id = DCQLClaimsQueryIdentifier(Random.nextBytes(32).encodeToString(Base64UrlStrict))
        val values = listOf<DCQLExpectedClaimValue>(
            DCQLExpectedClaimValue.StringValue("test")
        )
        val namespace = Base64.encode(Random.nextBytes(32))
        val claimName = Base64.encode(Random.nextBytes(32))

        val value = DCQLIsoMdocClaimsQuery(
            id = id,
            path = DCQLClaimsPathPointer(
                namespace,
                claimName
            ),
            values = values,
        )

        val correspondingJsonElement = buildJsonObject {
            put(DCQLClaimsQuery.SerialNames.ID, JsonPrimitive(id.string))
            put(DCQLClaimsQuery.SerialNames.VALUES, Json.encodeToJsonElement(values))
            put(DCQLClaimsQuery.SerialNames.PATH, buildJsonArray {
                add(namespace)
                add(claimName)
            })
        }

        val base: DCQLClaimsQuery = value
        val serialized = Json.encodeToJsonElement(base)

        serialized shouldBe correspondingJsonElement
        Json.decodeFromJsonElement<DCQLIsoMdocClaimsQuery>(correspondingJsonElement) shouldBe base
    }

    "execution" {
        val credential = mapOf(
            "testNamespace" to mapOf(
                "testClaimName" to JsonPrimitive(0),
                "otherClaimName" to JsonPrimitive(-1),
            ),
            "otherNamespace" to mapOf(
                "testClaimName" to JsonPrimitive(-1),
                "otherClaimName" to JsonPrimitive(-1)
            )
        )


        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            path = DCQLClaimsPathPointer(
                "testNamespace",
                "testClaimName",
            ),
            values = listOf(
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(0),
                DCQLExpectedClaimValue.BooleanValue(true),
            )
        ).executeClaimsQueryAgainstCredential(
            credentialStructure = DCQLCredentialClaimStructure.IsoMdocStructure(credential)
        ).getOrThrow().shouldBeInstanceOf<DCQLClaimsQueryResult.IsoMdocResult>().let {
            it.claimValue shouldBe JsonPrimitive(0)
        }

        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            path = DCQLClaimsPathPointer(
                "testNamespace",
                "testClaimName",
            ),
            values = listOf(
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(-1),
                DCQLExpectedClaimValue.BooleanValue(true),
            ),
        ).executeClaimsQueryAgainstCredential(
            credentialStructure = DCQLCredentialClaimStructure.IsoMdocStructure(credential)
        ).isSuccess shouldBe false
    }


    "value matching compares the JSON value of a data element (OpenID4VP 1.0, 6.3)" - {
        data class Case(val name: String, val claimValue: JsonElement, val expected: DCQLExpectedClaimValue, val matches: Boolean)
        listOf(
            Case("JSON string of a full-date", JsonPrimitive("1990-01-01"), DCQLExpectedClaimValue.StringValue("1990-01-01"), true),
            Case("JSON string of another date", JsonPrimitive("1990-01-01"), DCQLExpectedClaimValue.StringValue("1990-01-02"), false),
            Case("JSON number", JsonPrimitive(18), DCQLExpectedClaimValue.IntegerValue(18), true),
            Case("JSON number does not match its string", JsonPrimitive(18), DCQLExpectedClaimValue.StringValue("18"), false),
            Case("JSON string does not match a number", JsonPrimitive("18"), DCQLExpectedClaimValue.IntegerValue(18), false),
            Case("JSON boolean", JsonPrimitive(true), DCQLExpectedClaimValue.BooleanValue(true), true),
            Case("JSON array never matches", JsonArray(listOf(JsonPrimitive("AT"))), DCQLExpectedClaimValue.StringValue("AT"), false),
            Case("JSON null never matches", JsonNull, DCQLExpectedClaimValue.StringValue("null"), false),
        ).asData(nameFn = { it.name }) test { case ->
            DCQLIsoMdocClaimsQuery(
                path = DCQLClaimsPathPointer("namespace", "element"),
                values = listOf(case.expected),
            ).executeClaimsQueryAgainstCredential(
                credentialStructure = DCQLCredentialClaimStructure.IsoMdocStructure(
                    mapOf("namespace" to mapOf("element" to case.claimValue))
                )
            ).isSuccess shouldBe case.matches
        }
    }

    "needs to have exactly two path items" {
        val namespace = uuid4().toString()
        val claim = uuid4().toString()
        val identifier = DCQLClaimsQueryIdentifier(uuid4().toString())
        DCQLIsoMdocClaimsQuery(
            id = identifier,
            path = DCQLClaimsPathPointer(namespace, claim)
        )

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                path = DCQLClaimsPathPointer(namespace, claim, claim)
            )
        }

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                path = DCQLClaimsPathPointer(namespace)
            )
        }

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                path = DCQLClaimsPathPointer()
            )
        }
    }
}
