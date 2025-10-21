package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

val DCQLIsoMdocClaimsQueryTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLJsonClaimsQuery.SerialNames.PATH shouldBe "path"
        }
    }
    "instance serialization" {
        val id = DCQLClaimsQueryIdentifier(Random.Default.nextBytes(32).encodeToString(Base64UrlStrict))
        val values = listOf<DCQLExpectedClaimValue>(
            DCQLExpectedClaimValue.StringValue("test")
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
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(0),
                DCQLExpectedClaimValue.BooleanValue(true),
            )
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocStructure(it)
            },
            credentialQuery = DCQLIsoMdocCredentialQuery(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.MSO_MDOC,
                meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                    doctypeValue = "anything"
                )
            )
        ).getOrThrow().shouldBeInstanceOf<DCQLClaimsQueryResult.IsoMdocResult>().let {
            it.claimValue shouldBe 0
        }

        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            namespace = "testNamespace",
            claimName = "testClaimName",
            values = listOf(
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(-1),
                DCQLExpectedClaimValue.BooleanValue(true),
            )
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocStructure(it)
            },
            credentialQuery = DCQLIsoMdocCredentialQuery(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.MSO_MDOC,
                meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                    doctypeValue = "anything"
                )
            )
        ).isSuccess shouldBe false

        DCQLIsoMdocClaimsQuery(
            id = DCQLClaimsQueryIdentifier("test"),
            values = listOf(
                DCQLExpectedClaimValue.StringValue("test"),
                DCQLExpectedClaimValue.IntegerValue(0),
                DCQLExpectedClaimValue.BooleanValue(true),
            ),
            namespace = "testNamespace",
            claimName = "testClaimName",
        ).executeIsoMdocClaimsQueryAgainstCredential(
            credential = credential,
            credentialStructureExtractor = {
                DCQLCredentialClaimStructure.IsoMdocStructure(it)
            },
            credentialQuery = DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier(
                    Random.nextBytes(32).encodeToString(Base64UrlStrict),
                ),
                format = CredentialFormatEnum.DC_SD_JWT,
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf("anything")
                )
            )
        ).isSuccess shouldBe false
    }

    "new and old parameters need to match" {
        val namespace = uuid4().toString()
        val claim = uuid4().toString()
        val identifier = DCQLClaimsQueryIdentifier(uuid4().toString())
        DCQLIsoMdocClaimsQuery(
            id = identifier,
            namespace = namespace,
            claimName = claim,
            path = DCQLClaimsPathPointer(namespace, claim)
        )

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                namespace = namespace,
                claimName = claim,
                path = DCQLClaimsPathPointer(namespace.reversed(), claim)
            )
        }

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                namespace = namespace,
                claimName = claim,
                path = DCQLClaimsPathPointer(namespace, claim.reversed())
            )
        }

        shouldThrow<IllegalArgumentException> {
            DCQLIsoMdocClaimsQuery(
                id = identifier,
                namespace = namespace,
                claimName = claim,
                path = DCQLClaimsPathPointer(claim, namespace)
            )
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

