package at.asitplus.wallet.lib.validation

import at.asitplus.catchingUnwrapped
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The disclosures of an SD-JWT, processed strictly against its issuer-signed payload.
 */
internal class ProcessedDisclosures(
    /** One entry per supplied disclosure, in the order supplied. */
    val items: List<DisclosedItemValidation>,
    /** The issuer-signed payload with every referenced disclosure applied. */
    val payload: JsonObject,
    /** Serialized disclosure to parsed item, for every supplied disclosure that is valid. */
    val disclosures: Map<String, SelectiveDisclosureItem>,
    /**
     * Position of each claim in [payload] that a valid disclosure introduced, to that serialized disclosure. Array
     * indices count the elements of [payload], i.e. without decoys and withheld elements (RFC 9901, 7.1 step 3.d).
     */
    val disclosuresByPath: Map<DCQLClaimsPathPointer, String>,
    /** Positions in [payload] of the arrays that, as issued, contain array element digests (RFC 9901, 4.2.4.2). */
    val arraysWithElementDigests: Set<DCQLClaimsPathPointer>,
    /** Whether a digest occurs more than once in the payload, directly or recursively via disclosures. */
    val duplicateDigest: Boolean,
)

/**
 * Processes [rawDisclosures] against [signedPayload], hashing each with [digest] over its original base64url string,
 * as the Holder or Verifier has to (RFC 9901, 7.1 *Verification of the SD-JWT*, step 3), but reporting every supplied
 * disclosure instead of aborting at the first problem:
 *  - `parsing`: decodes to a JSON array of two or three elements (RFC 9901, 4.2), without normalizing the input
 *  - `digest`: referenced by a digest in the payload, directly or recursively via other disclosures (step 5)
 *  - `structure`: an object property disclosure (three elements) for an `_sd` digest, whose claim name is not `_sd`
 *    or `...` and does not exist at that level already, an array element disclosure (two elements) for a `...`
 *    digest (step 3.c), and neither the disclosure nor its digest occur twice (step 4)
 *
 * A digest without a supplied disclosure is ignored, i.e. a withheld claim (step 3.c.i), and its array element
 * removed (step 3.d). `_sd` keys and `_sd_alg` are removed from the result (steps 3.e and 3.f).
 *
 * A disclosure of one of the [notDisclosable] claims at the top level of the payload fails its structure check.
 */
internal fun processDisclosures(
    rawDisclosures: List<String>,
    signedPayload: JsonObject,
    digest: Digest,
    notDisclosable: Set<String> = emptySet(),
): ProcessedDisclosures = DisclosureProcessor(rawDisclosures, digest, notDisclosable).process(signedPayload)

private class DisclosureProcessor(
    private val rawDisclosures: List<String>,
    digest: Digest,
    private val notDisclosable: Set<String>,
) {
    private val parsed: List<Result<SelectiveDisclosureItem>> = rawDisclosures.map { raw ->
        catchingUnwrapped {
            joseCompliantSerializer.decodeFromString<SelectiveDisclosureItem>(
                raw.decodeToByteArray(Base64UrlStrict).decodeToString()
            )
        }
    }
    private val indexByDigest = mutableMapOf<String, Int>()
    private val structureFailures = mutableMapOf<Int, Throwable>()
    private val referenced = mutableSetOf<Int>()
    private val seenDigests = mutableSetOf<String>()
    private var duplicateDigest = false
    private val disclosuresByPath = mutableMapOf<DCQLClaimsPathPointer, String>()
    private val arraysWithElementDigests = mutableSetOf<DCQLClaimsPathPointer>()

    init {
        rawDisclosures.forEachIndexed { index, raw ->
            val hash = raw.hashDisclosure(digest)
            if (hash in indexByDigest) {
                structureFailures[index] = IllegalArgumentException("The disclosure is supplied more than once")
            } else {
                indexByDigest[hash] = index
            }
        }
    }

    fun process(signedPayload: JsonObject): ProcessedDisclosures {
        val processed = processObject(signedPayload, path = emptyList(), topLevel = true)
        val payload = JsonObject(processed - SdJwtConstants.SD_ALG)
        val items = rawDisclosures.indices.map { index -> validation(index) }
        val valid = items.withIndex()
            .filter { (_, item) -> item.parsing == Passed && item.digest == Passed && item.structure == Passed }
            .associate { (index, _) -> rawDisclosures[index] to parsed[index].getOrThrow() }
        // A disclosure applied before it failed its structure check, e.g. for a repeated digest, is not valid
        val validByPath = disclosuresByPath.filterValues { it in valid }
        return ProcessedDisclosures(items, payload, valid, validByPath, arraysWithElementDigests, duplicateDigest)
    }

    private fun validation(index: Int): DisclosedItemValidation {
        val item = parsed[index]
        val reference = DisclosedItemReference.SdJwt(index, item.getOrNull()?.claimName)
        val parsing = item.fold(onSuccess = { Passed }, onFailure = { Failed(it) })
        if (parsing != Passed)
            return DisclosedItemValidation(reference, parsing, Blocked(), Blocked())
        val isReferenced = index in referenced
        return DisclosedItemValidation(
            reference = reference,
            parsing = parsing,
            digest = if (isReferenced) Passed
            else Failed(IllegalArgumentException("The disclosure is not referenced by the issuer-signed payload")),
            structure = structureFailures[index]?.let { Failed(it) } ?: if (isReferenced) Passed else Blocked(),
        )
    }

    /** The disclosure for [digestValue], marked as referenced, or `null` for a withheld claim or a decoy. */
    private fun disclosureFor(digestValue: String): Int? {
        if (!seenDigests.add(digestValue)) {
            duplicateDigest = true
            indexByDigest[digestValue]?.let { failStructure(it, duplicateDigestError()) }
            return null
        }
        return indexByDigest[digestValue]?.also { referenced += it }
    }

    private fun processObject(
        input: JsonObject,
        path: List<DCQLClaimsPathPointerSegment>,
        topLevel: Boolean = false,
    ): Map<String, JsonElement> {
        val output = linkedMapOf<String, JsonElement>()
        input.forEach { (name, value) ->
            if (name != SdJwtConstants.NAME_SD) output[name] = processValue(value, path + NameSegment(name))
        }
        val digests = (input[SdJwtConstants.NAME_SD] as? JsonArray).orEmpty()
            .mapNotNull { (it as? JsonPrimitive)?.takeIf { it.isString }?.content }
        digests.forEach { digestValue ->
            val index = disclosureFor(digestValue) ?: return@forEach
            val item = parsed[index].getOrNull() ?: return@forEach
            val claimName = item.claimName
            val problem = when {
                claimName == null -> "An array element disclosure is referenced from an object"
                claimName == SdJwtConstants.NAME_SD || claimName == "..." -> "The claim name $claimName is reserved"
                claimName in output -> "The claim name $claimName exists already at this level"
                topLevel && claimName in notDisclosable -> "The claim $claimName must not be selectively disclosed"
                else -> null
            }
            if (problem != null || claimName == null) {
                failStructure(index, IllegalArgumentException(problem))
            } else {
                val position = path + NameSegment(claimName)
                disclosuresByPath[position.toPointer()] = rawDisclosures[index]
                output[claimName] = processValue(item.claimValue, position)
            }
        }
        return output
    }

    /** Positions count only the elements kept, so decoys and withheld elements shift no index (step 3.d). */
    private fun processArray(input: JsonArray, path: List<DCQLClaimsPathPointerSegment>): JsonArray {
        val output = mutableListOf<JsonElement>()
        input.forEach { element ->
            val position = path + IndexSegment(output.size.toUInt())
            val digestValue = (element as? JsonObject)
                ?.takeIf { it.size == 1 }
                ?.let { it["..."] as? JsonPrimitive }
                ?.takeIf { it.isString }
                ?.content
            if (digestValue == null) {
                output += processValue(element, position)
                return@forEach
            }
            arraysWithElementDigests += path.toPointer()
            val index = disclosureFor(digestValue) ?: return@forEach
            val item = parsed[index].getOrNull() ?: return@forEach
            if (item.claimName != null) {
                val problem = "An object property disclosure is referenced from an array"
                failStructure(index, IllegalArgumentException(problem))
            } else {
                disclosuresByPath[position.toPointer()] = rawDisclosures[index]
                output += processValue(item.claimValue, position)
            }
        }
        return JsonArray(output)
    }

    private fun processValue(
        value: JsonElement,
        path: List<DCQLClaimsPathPointerSegment>
    ): JsonElement = when (value) {
        is JsonObject -> JsonObject(processObject(value, path))
        is JsonArray -> processArray(value, path)
        else -> value
    }

    /** Every position below the root is non-empty: the root of an SD-JWT payload is an object. */
    private fun List<DCQLClaimsPathPointerSegment>.toPointer() = DCQLClaimsPathPointer(toNonEmptyList())

    /** Keeps the first structure failure of a disclosure. */
    private fun failStructure(index: Int, failure: Throwable) {
        val _ = structureFailures.getOrPut(index) { failure }
    }

    private fun duplicateDigestError() =
        IllegalArgumentException("The digest of the disclosure occurs more than once in the issuer-signed payload")
}
