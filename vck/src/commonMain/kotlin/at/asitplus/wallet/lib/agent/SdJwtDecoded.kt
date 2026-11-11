package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.validation.ProcessedDisclosures
import at.asitplus.wallet.lib.validation.processDisclosures
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * An SD-JWT with its supplied disclosures applied, as the Holder or Verifier processes it (RFC 9901, 7.1
 * *Verification of the SD-JWT*, step 3). It is the one view of the claims of an SD-JWT: the claims to match, the
 * disclosures to present and the positions of array elements are all derived from it, so they agree by construction.
 *
 * See [Selective Disclosure for JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc9901)
 */
class SdJwtDecoded internal constructor(
    val sdJwtSigned: SdJwtSigned,
    processed: ProcessedDisclosures,
) {
    /**
     * Applies every disclosure of [sdJwtSigned] that its issuer-signed payload references, hashed with the algorithm
     * of `_sd_alg`, or SHA-256 if it is absent (RFC 9901, 4.1.1) or not understood. Invalid disclosures are ignored.
     */
    @Throws(IllegalArgumentException::class)
    constructor(sdJwtSigned: SdJwtSigned) : this(sdJwtSigned, sdJwtSigned.processDisclosures())

    /**
     * The issuer-signed payload with every valid disclosure applied: `_sd` and `_sd_alg` are removed, empty objects and
     * arrays are kept (RFC 9901, 7.1 steps 3.d to 3.f).
     */
    val reconstructedJsonObject: JsonObject = processed.payload

    /** Map of serialized disclosure item (as [String]) to parsed item, for every valid disclosure. */
    val validDisclosures: Map<String, SelectiveDisclosureItem> = processed.disclosures

    /**
     * The position of each claim in [reconstructedJsonObject] that a disclosure introduced, to that serialized
     * disclosure. Array indices count the elements of [reconstructedJsonObject], i.e. without decoy digests and
     * withheld elements (RFC 9901, 7.1 step 3.d).
     */
    val disclosuresByPath: Map<DCQLClaimsPathPointer, String> = processed.disclosuresByPath

    /**
     * The positions in [reconstructedJsonObject] of the arrays that, as issued, contain array element digests
     * (RFC 9901, 4.2.4.2): a verifier can not tell the position of an element as issued in them, as it can not tell
     * withheld elements from decoys (4.2.5).
     */
    val arraysWithElementDigests: Set<DCQLClaimsPathPointer> = processed.arraysWithElementDigests

    /**
     * The disclosures to present for the claims [pointers] select in [reconstructedJsonObject]: for each selected
     * claim its own disclosure, those of its ancestors, without which a verifier can not reach its digest (RFC 9901,
     * 7.2), and those of its sub-claims, which it includes as its value (OpenID4VP 1.0, 7.3), but no others, as
     * "Wallets MUST NOT send selectively disclosable claims that have not been selected" (OpenID4VP 1.0, 6.4).
     */
    fun disclosuresFor(pointers: Collection<DCQLClaimsPathPointer>): Set<String> = pointers
        .flatMap { it.query(reconstructedJsonObject) }
        .map { it.normalizedJsonPath.toDCQLClaimsPathPointer() }
        .flatMapTo(mutableSetOf()) { selected ->
            disclosuresByPath.filterKeys { it.startsWith(selected) || selected.startsWith(it) }.values
        }

    override fun equals(other: Any?): Boolean = other is SdJwtDecoded &&
            sdJwtSigned == other.sdJwtSigned &&
            reconstructedJsonObject == other.reconstructedJsonObject &&
            validDisclosures == other.validDisclosures

    override fun hashCode(): Int = 31 * sdJwtSigned.hashCode() + reconstructedJsonObject.hashCode()

    override fun toString(): String = "SdJwtDecoded(reconstructedJsonObject=$reconstructedJsonObject)"
}

private fun SdJwtSigned.processDisclosures(): ProcessedDisclosures {
    val payload = jws.getPayload<JsonObject>().getOrThrow()
    val digest = payload[SdJwtConstants.SD_ALG]?.jsonPrimitive?.content.toDigest() ?: Digest.SHA256
    return processDisclosures(rawDisclosures, payload, digest)
}

private fun DCQLClaimsPathPointer.startsWith(prefix: DCQLClaimsPathPointer) =
    size >= prefix.size && subList(0, prefix.size) == prefix.toList()

/** The concrete path of a claim selected by [DCQLClaimsPathPointer.query], until that returns claims path pointers. */
internal fun NormalizedJsonPath.toDCQLClaimsPathPointer() = DCQLClaimsPathPointer(
    map {
        when (it) {
            is NormalizedJsonPathSegment.NameSegment -> NameSegment(it.memberName)
            is NormalizedJsonPathSegment.IndexSegment -> IndexSegment(it.index)
        }
    }.toNonEmptyList()
)
