package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import kotlinx.serialization.json.*
import kotlin.random.Random

/**
 * See [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html#name-simple-structured-sd-jwt)
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
    fun Collection<ClaimToBeIssued>.toSdJsonObject()
            : Pair<JsonObject, Collection<String>> = mutableListOf<String>().let { disclosures ->
        buildJsonObject {
            with(customPartition()) {
                val objectClaimDigests: Collection<String> = recursiveClaims.mapNotNull { claim ->
                    claim.value as Collection<*>
                    (claim.value.filterIsInstance<ClaimToBeIssued>()).toSdJsonObject().let {
                        if (claim.selectivelyDisclosable) {
                            disclosures.addAll(it.second)
                            put(claim.name, it.first)
                            claim.toSdItem(it.first).toDisclosure()
                                .also { disclosures.add(it) }
                                .hashDisclosure()
                        } else {
                            disclosures.addAll(it.second)
                            put(claim.name, it.first)
                            null
                        }
                    }
                }
                val dotNotationClaims: Collection<String> = dotNotation.groupByDots().mapNotNull { (key, claims) ->
                    claims.toSdJsonObject().let {
                        disclosures.addAll(it.second)
                        put(key, it.first)
                        key.toSdItem(it.first).toDisclosure()
                            .also { disclosures.add(it) }
                            .hashDisclosure()
                    }
                }
                val dotNotationClaimsPlain: Collection<String> =
                    dotNotationPlain.groupByDots().mapNotNull { (key, claims) ->
                        claims.toSdJsonObject().let {
                            disclosures.addAll(it.second)
                            put(key, it.first)
                            null
                        }
                    }
                val singleClaimsDigests: Collection<String> = claimsWithSimpleValue.mapNotNull { claim ->
                    if (claim.selectivelyDisclosable) {
                        claim.toSdItem().toDisclosure()
                            .also { disclosures.add(it) }
                            .hashDisclosure()
                    } else {
                        put(claim.name, claim.value.toJsonElement())
                        null
                    }
                }
                (objectClaimDigests + dotNotationClaims + dotNotationClaimsPlain + singleClaimsDigests).let { digests ->
                    if (digests.isNotEmpty())
                        putJsonArray("_sd") { addAll(digests) }
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
     * Holds all the claims to be issued split up into four categories, for easy use in [toSdJsonObject]
     */
    data class Partitioned(
        val recursiveClaims: Collection<ClaimToBeIssued>,
        val dotNotation: Collection<ClaimToBeIssued>,
        val dotNotationPlain: Collection<ClaimToBeIssued>,
        val claimsWithSimpleValue: Collection<ClaimToBeIssued>,
    )

    /**
     * Partitions the claims to be issued into four categories, for easy use in [toSdJsonObject]
     */
    private fun Collection<ClaimToBeIssued>.customPartition(): Partitioned {
        val isDotNotation: (ClaimToBeIssued) -> Boolean = { it.name.contains('.') }
        val isDisclosable: (ClaimToBeIssued) -> Boolean = { it.selectivelyDisclosable }
        val hasCollectionValue: (ClaimToBeIssued) -> Boolean =
            { it.value is Collection<*> && it.value.first() is ClaimToBeIssued }
        val (collectionClaims, simpleValueClaims) = partition(hasCollectionValue)
        val dotNotationClaims = simpleValueClaims.filter(isDotNotation)
        return Partitioned(
            collectionClaims,
            dotNotationClaims.filter(isDisclosable),
            dotNotationClaims.filterNot(isDisclosable),
            simpleValueClaims.filterNot(isDotNotation)
        )
    }

    private fun String.toSdItem(claimValue: JsonElement) =
        SelectiveDisclosureItem(Random.nextBytes(32), this, claimValue)

    private fun ClaimToBeIssued.toSdItem(claimValue: JsonObject) =
        SelectiveDisclosureItem(Random.nextBytes(32), name, claimValue)

    private fun ClaimToBeIssued.toSdItem() =
        SelectiveDisclosureItem(Random.nextBytes(32), name, value)

}
