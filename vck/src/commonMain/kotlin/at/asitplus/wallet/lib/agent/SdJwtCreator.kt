package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.agent.SdJwtCreator.disallowedNames
import at.asitplus.wallet.lib.agent.SdJwtCreator.toIntSdJsonObject
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SdJwtConstants.SD_ALG
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.fromAnyValue
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlin.collections.plus


/**
 * See [Selective Disclosure for JSON Web Tokens](https://www.rfc-editor.org/rfc/rfc9901.html)
 */
object SdJwtCreator {

    /**
     * Creates a JSON object to contain only digests for the selectively disclosable claims
     * (in the array with key `_sd`), and the plain values for
     * other claims that are not selectively disclosable (see [ClaimToBeIssued.selectivelyDisclosable]).
     *
     * Supports creating nested structures in two ways:
     *  - The [ClaimToBeIssued] contains a collection of other [ClaimToBeIssued] in [ClaimToBeIssued.value]
     *  - The [ClaimToBeIssued.name] contains dots (`.`) to nest structures, e.g. `address.region`
     *
     * @return The encoded JSON object and the disclosure strings
     */
    fun Collection<ClaimToBeIssued>.toSdJsonObject(
        randomSource: RandomSource = RandomSource.Secure,
        digest: Digest = Digest.SHA256,
    ): Pair<JsonObject, Collection<String>> {
        val result = toIntSdJsonObject(randomSource, digest)
        return result.first.withAlg(digest) to result.second
    }

    private fun JsonObject.withAlg(digest: Digest): JsonObject =
        JsonObject(this + (SD_ALG to digest.toIanaName().toJsonElement()))

    fun Collection<ClaimToBeIssued>.toIntSdJsonObject(
        randomSource: RandomSource = RandomSource.Secure,
        digest: Digest = Digest.SHA256,
    ): Pair<JsonObject, Collection<String>> = mutableListOf<String>().let { disclosures ->
        buildJsonObject {
            with(honorNotDisclosableClaims().customPartition()) {
                val recursiveDigests = recursive.mapNotNull { claim ->
                    claim.value as Collection<*>
                    (claim.value.filterIsInstance<ClaimToBeIssued>()).toIntSdJsonObject(randomSource, digest).let {
                        if (claim.selectivelyDisclosable) {
                            disclosures.addAll(it.second)
                            claim.toSdItem(it.first, randomSource).toDisclosure()
                                .also { disclosures.add(it) }
                                .hashDisclosure(digest)
                        } else {
                            disclosures.addAll(it.second)
                            put(claim.name, it.first)
                            null
                        }
                    }
                }
                val dotNotationDigests = dotNotation.groupByDots().mapNotNull { (key, claims) ->
                    claims.toIntSdJsonObject(randomSource, digest).let {
                        disclosures.addAll(it.second)
                        put(key, it.first)
                        key.toSdItem(it.first, randomSource).toDisclosure()
                            .also { disclosures.add(it) }
                            .hashDisclosure(digest)
                    }
                }
                val dotNotationPlainDigests = dotNotationPlain.groupByDots().mapNotNull { (key, claims) ->
                    claims.toIntSdJsonObject(randomSource, digest).let {
                        disclosures.addAll(it.second)
                        put(key, it.first)
                        null
                    }
                }
                val simpleDigests = simpleValues.mapNotNull { claim ->
                    if (claim.selectivelyDisclosable) {
                        claim.toSdItem(randomSource).toDisclosure()
                            .also { disclosures.add(it) }
                            .hashDisclosure(digest)
                    } else {
                        put(claim.name, claim.value.toJsonElement())
                        null
                    }
                }
                (recursiveDigests + dotNotationDigests + dotNotationPlainDigests + simpleDigests).let { digests ->
                    if (digests.isNotEmpty()) {
                        putJsonArray(NAME_SD) { addAll(digests) }
                    }
                }
            }
        } to disclosures
    }

    /**
     * Groups by the object name (the part before the first `.`),
     * with the list of values containing the original values, but the name stripped,
     * i.e. the part before the first `.` removed.
     *
     * Example:
     * ```
     * {
     *   "address.region": "Vienna",
     *   "address.country": "AT"
     * }
     * ```
     * turns into
     * ```
     * {
     *   "address": {
     *     "region": "Vienna",
     *     "country": "AT"
     *   }
     * }
     */
    private fun Collection<ClaimToBeIssued>.groupByDots(): Map<String, List<ClaimToBeIssued>> = groupBy(
        { it.name.split(".").first() },
        { it.copy(name = it.name.split(".").drop(1).joinToString()) }
    ).toMap()

    /**
     * Holds all the claims to be issued split up into four categories, for easy use in [toIntSdJsonObject]
     */
    data class Partitioned(
        val recursive: Collection<ClaimToBeIssued>,
        val dotNotation: Collection<ClaimToBeIssued>,
        val dotNotationPlain: Collection<ClaimToBeIssued>,
        val simpleValues: Collection<ClaimToBeIssued>,
        val arrays: Collection<ClaimToBeIssued>,
    )

    /** See [registered JWT claims](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/). */
    private val notDisclosableClaims = listOf(
        "iss", "nbf", "exp", "cnf", "vct", "status"
    )

    /** See [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html#name-issuer-signed-jwt). */
    private val disallowedNames = listOf(
        SD_ALG, "..."
    )

    /**
     * Honors list of
     * [registered JWT claims](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
     * and prevents claims of that names to be selectively disclosed,
     * as well as [disallowedNames] which covers constants used in the SD-JWT VC itself.
     */
    private fun Collection<ClaimToBeIssued>.honorNotDisclosableClaims(): Collection<ClaimToBeIssued> =
        this.map {
            if (it.name in notDisclosableClaims) {
                it.copy(it.name, it.value, false)
            } else if (it.name.contains(".") && it.name.split(":").first() in notDisclosableClaims) {
                it.copy(it.name, it.value, false)
            } else {
                it
            }
        }.filterNot { it.name in disallowedNames }

    /**
     * Partitions the claims to be issued into four categories, for easy use in [toIntSdJsonObject]
     */
    private fun Collection<ClaimToBeIssued>.customPartition(): Partitioned {
        val isDotNotation: (ClaimToBeIssued) -> Boolean = { it.name.contains('.') }
        val isArrayClaim: (ClaimToBeIssued) -> Boolean =
            { it.value is Collection<*> && it.value.first() is ClaimToBeIssuedArrayElement }
        val isDisclosable: (ClaimToBeIssued) -> Boolean = { it.selectivelyDisclosable }
        val hasNestedElements: (ClaimToBeIssued) -> Boolean =
            { it.value is Collection<*> && it.value.first() is ClaimToBeIssued }
        val (recursiveClaims, simpleValueClaims) = partition(hasNestedElements)
        val dotNotationClaims = simpleValueClaims.filter(isDotNotation)
        val arrayClaims = simpleValueClaims.filter(isArrayClaim)
        return Partitioned(
            recursive = recursiveClaims,
            dotNotation = dotNotationClaims.filter(isDisclosable),
            dotNotationPlain = dotNotationClaims.filterNot(isDisclosable),
            simpleValues = simpleValueClaims - dotNotationClaims - arrayClaims,
            arrays = arrayClaims
        )
    }

    private fun String.toSdItem(
        claimValue: JsonElement,
        randomSource: RandomSource = RandomSource.Secure,
    ) = SelectiveDisclosureItem(
        salt = randomSource.nextBytes(32),
        claimName = this,
        claimValue = claimValue
    )

    private fun ClaimToBeIssued.toSdItem(
        claimValue: JsonObject,
        randomSource: RandomSource = RandomSource.Secure,
    ) = SelectiveDisclosureItem(
        salt = randomSource.nextBytes(32),
        claimName = name,
        claimValue = claimValue
    )

    private fun ClaimToBeIssued.toSdItem(
        randomSource: RandomSource = RandomSource.Secure,
    ) = SelectiveDisclosureItem.fromAnyValue(
        salt = randomSource.nextBytes(32),
        claimName = name,
        claimValue = value
    )

}
