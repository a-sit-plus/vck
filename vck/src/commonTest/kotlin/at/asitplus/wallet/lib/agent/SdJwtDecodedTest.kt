package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonArray
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.random.Random

val SdJwtDecodedTest by matrixSuite {

    "reconstructs the claims as RFC 9901, 7.1 step 3 processes them" {
        // Decoys removed (3.c.i, 3.d), {} kept (3.e), nested arrays processed (3.c.iii.3), _sd and _sd_alg removed
        sdJwtDecodedExample().decoded.reconstructedJsonObject shouldBe Json.parseToJsonElement(
            """
            {
              "vct": "https://example.com/unknown",
              "address": {},
              "m": [["X", "Y"]],
              "e": [{}, "E1"],
              "nationalities": ["DE", "FR"],
              "degrees": [
                {"type": "Bachelor of Science", "university": "University of Betelgeuse"},
                {"type": "Master of Science", "university": "University of Betelgeuse"}
              ]
            }
            """
        ).jsonObject
    }

    "indexes each disclosure by the position of its claim, counting no decoys" {
        val example = sdJwtDecodedExample()
        example.decoded.disclosuresByPath shouldBe mapOf(
            pointer("nationalities") to example["nat"],
            pointer("nationalities", 0) to example["de"],
            pointer("nationalities", 1) to example["fr"],
            pointer("degrees") to example["deg"],
            pointer("degrees", 0, "university") to example["u0"],
            pointer("degrees", 1) to example["d1"],
            pointer("degrees", 1, "university") to example["u1"],
            pointer("m", 0, 0) to example["x"],
            pointer("m", 0, 1) to example["y"],
            pointer("e", 1) to example["e1"],
        )
    }

    "marks the arrays that contain array element digests as issued" {
        sdJwtDecodedExample().decoded.arraysWithElementDigests shouldBe
                setOf(pointer("nationalities"), pointer("degrees"), pointer("m", 0), pointer("e"))
    }

    listOf(
        SelectionCase("an array element with its parent", pointer("nationalities", 1), "nat", "fr"),
        SelectionCase("all array elements", pointer("nationalities", null), "nat", "de", "fr"),
        SelectionCase("a plain claim in disclosed elements", pointer("degrees", null, "type"), "deg", "d1"),
        SelectionCase("a claim with all its sub-claims", pointer("degrees"), "deg", "u0", "d1", "u1"),
        SelectionCase("a nested claim with its ancestors", pointer("degrees", 1, "university"), "deg", "d1", "u1"),
        SelectionCase("an element of a nested array", pointer("m", 0, 1), "y"),
        SelectionCase("an element after an empty object", pointer("e", 1), "e1"),
        SelectionCase("an empty object", pointer("e", 0)),
        SelectionCase("a plain claim", pointer("vct")),
        SelectionCase("a missing claim", pointer("missing")),
    ).forEach { case ->
        "disclosuresFor selects ${case.name}" {
            val example = sdJwtDecodedExample()
            example.decoded.disclosuresFor(listOf(case.pointer)) shouldBe case.expected.map { example[it] }.toSet()
        }
    }

    "is equal for the same SD-JWT" {
        val sdJwtSigned = sdJwtDecodedExample().decoded.sdJwtSigned
        SdJwtDecoded(sdJwtSigned) shouldBe SdJwtDecoded(sdJwtSigned)
    }
}

private class SelectionCase(val name: String, val pointer: DCQLClaimsPathPointer, vararg val expected: String)

/** A serialized SD-JWT, its [decoded] view, and its serialized disclosures by name. */
internal class SdJwtDecodedExample(
    val serialized: String,
    val decoded: SdJwtDecoded,
    private val disclosures: Map<String, String>,
) {
    operator fun get(name: String) = disclosures.getValue(name)
}

/** A claims path pointer of names, indices (as [Int]) and `null`. */
internal fun pointer(vararg segments: Any?) = DCQLClaimsPathPointer(
    segments.map {
        when (it) {
            is String -> NameSegment(it)
            is Int -> IndexSegment(it.toUInt())
            null -> NullSegment
            else -> throw IllegalArgumentException("Not a segment: $it")
        }
    }.toNonEmptyList()
)

/**
 * The example credential of OpenID4VP 1.0, 7.3, with decoy digests (RFC 9901, 4.2.5) in `_sd` and in arrays, an object
 * and an array element without disclosed members, and an array nested in an array.
 */
internal suspend fun sdJwtDecodedExample(): SdJwtDecodedExample {
    val disclosures = linkedMapOf<String, String>()
    fun disclose(name: String, content: JsonArray): String =
        content.toString().encodeToByteArray().encodeToString(Base64UrlStrict)
            .also { disclosures[name] = it }
            .hashDisclosure()

    fun salt() = Random.nextBytes(16).encodeToString(Base64UrlStrict)
    fun property(name: String, claimName: String, value: JsonElement) =
        disclose(name, buildJsonArray { add(salt()); add(claimName); add(value) })

    fun element(name: String, value: String) = disclose(name, buildJsonArray { add(salt()); add(value) })
    fun decoy() = Random.nextBytes(32).encodeToString(Base64UrlStrict)
    fun digests(vararg digests: String) = buildJsonArray { digests.forEach { add(it) } }
    fun elementDigest(digest: String) = buildJsonObject { put("...", digest) }

    val de = element("de", "DE")
    val fr = element("fr", "FR")
    val nat = property("nat", "nationalities", JsonArray(listOf(decoy(), de, fr).map(::elementDigest)))
    val u0 = property("u0", "university", JsonPrimitive("University of Betelgeuse"))
    val u1 = property("u1", "university", JsonPrimitive("University of Betelgeuse"))
    val d1 = disclose("d1", buildJsonArray {
        add(salt())
        addJsonObject { put("type", "Master of Science"); put("_sd", digests(u1)) }
    })
    val deg = property("deg", "degrees", buildJsonArray {
        addJsonObject { put("type", "Bachelor of Science"); put("_sd", digests(u0)) }
        add(elementDigest(d1))
    })
    val x = element("x", "X")
    val y = element("y", "Y")
    val e1 = element("e1", "E1")
    val payload = buildJsonObject {
        put("vct", "https://example.com/unknown")
        put("_sd", digests(nat, deg, decoy()))
        putJsonObject("address") { put("_sd", digests(decoy())) }
        putJsonArray("m") { addJsonArray { listOf(decoy(), x, y).forEach { add(elementDigest(it)) } } }
        putJsonArray("e") {
            addJsonObject { put("_sd", digests(decoy())) }
            add(elementDigest(e1))
        }
        put("_sd_alg", "sha-256")
    }
    val jws = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
        JwsContentTypeConstants.SD_JWT,
        payload,
        JsonObject.serializer(),
    ).getOrThrow()
    val serialized = (listOf(jws.jws.toString()) + disclosures.values).joinToString("~", postfix = "~")
    val decoded = SdJwtDecoded(SdJwtSigned.parseCatching(serialized).getOrThrow())
    return SdJwtDecodedExample(serialized, decoded, disclosures)
}
