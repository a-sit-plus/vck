package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.agent.SdJwtCreator.disallowedNames
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SdJwtConstants.NAME_SD
import at.asitplus.wallet.lib.data.SdJwtConstants.SD_ALG
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.fromAnyValue
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray


/**
 * See [Selective Disclosure for JSON Web Tokens](https://datatracker.ietf.org/doc/html/rfc9901)
 */
object SdJwtCreator {

    /**
     * Creates a JSON object to contain only digests for the selectively disclosable claims
     * (in the array with key `_sd`), and the plain values for
     * other claims that are not selectively disclosable (see [ClaimToBeIssued.selectivelyDisclosable]).
     *
     * To create nested structures, pass a collection of [ClaimToBeIssued] in [ClaimToBeIssued.value].
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
                val recursiveDigests: Collection<String> = recursive.mapNotNull { claim ->
                    claim.value as Collection<*>
                    val recursiveClaims = claim.value.filterIsInstance<ClaimToBeIssued>()
                    val arrayClaims = claim.value.filterIsInstance<ClaimToBeIssuedArrayElement>()
                    require(recursiveClaims.size + arrayClaims.size == claim.value.size) {
                        "All elements of a recursive claim must be either ClaimToBeIssued or ClaimToBeIssuedArrayElement"
                    }
                    require(recursiveClaims.isEmpty() || arrayClaims.isEmpty()) {
                        "Recursive claims must not mix ClaimToBeIssued and ClaimToBeIssuedArrayElement"
                    }
                    val mapped = if (recursiveClaims.isNotEmpty())
                        recursiveClaims.toIntSdJsonObject(randomSource, digest)
                    else
                        arrayClaims.toArraySdJsonObject(randomSource, digest)
                    mapped.let {
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
                val simpleDigests: Collection<String> = simpleValues.mapNotNull { claim ->
                    if (claim.selectivelyDisclosable) {
                        claim.toSdItem(randomSource).toDisclosure()
                            .also { disclosures.add(it) }
                            .hashDisclosure(digest)
                    } else {
                        put(claim.name, claim.value.toJsonElement())
                        null
                    }
                }
                (recursiveDigests + simpleDigests).let { digests ->
                    if (digests.isNotEmpty()) {
                        putJsonArray(NAME_SD) { addAll(digests) }
                    }
                }
            }
        } to disclosures
    }

    private fun Collection<ClaimToBeIssuedArrayElement>.toArraySdJsonObject(
        randomSource: RandomSource = RandomSource.Secure,
        digest: Digest = Digest.SHA256,
    ): Pair<JsonElement, Collection<String>> = mutableListOf<String>().let { disclosures ->
        buildJsonArray {
            forEach { claim ->
                if (claim.selectivelyDisclosable) {
                    val hashed = claim.toSdItem(randomSource).toDisclosure()
                        .also { disclosures.add(it) }
                        .hashDisclosure(digest)
                    add(buildJsonObject {
                        put("...", JsonPrimitive(hashed))
                    })
                } else {
                    add(claim.value.toJsonElement())
                }
            }
        } to disclosures
    }

    /**
     * Holds all the claims to be issued split up into two categories, for easy use in [toIntSdJsonObject]
     */
    data class Partitioned(
        val recursive: Collection<ClaimToBeIssued>,
        val simpleValues: Collection<ClaimToBeIssued>,
    )

    /** See [SD-JWT VC draft 17](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-17.html). */
    private val notDisclosableClaims = listOf(
        "iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"
    )

    /** See [RFC 9901](https://datatracker.ietf.org/doc/html/rfc9901). */
    private val disallowedNames = listOf(
        NAME_SD, SD_ALG, "..."
    )

    /**
     * Honors list of
     * [registered JWT claims](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
     * and prevents claims of that names to be selectively disclosed,
     * as well as [disallowedNames] which covers constants used in the SD-JWT VC itself.
     */
    private fun Collection<ClaimToBeIssued>.honorNotDisclosableClaims(): Collection<ClaimToBeIssued> =
        this.map {
            if (it.name in notDisclosableClaims) it.copy(it.name, it.value, false) else it
        }.filterNot { it.name in disallowedNames }

    /**
     * Partitions the claims to be issued into two categories, for easy use in [toIntSdJsonObject]
     */
    private fun Collection<ClaimToBeIssued>.customPartition(): Partitioned {
        val (recursiveClaims, simpleValueClaims) = partition {
            it.value is Collection<*> &&
                    (it.value.first() is ClaimToBeIssued || it.value.first() is ClaimToBeIssuedArrayElement)
        }
        return Partitioned(recursive = recursiveClaims, simpleValues = simpleValueClaims)
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
        claimValue: JsonElement,
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

    private fun ClaimToBeIssuedArrayElement.toSdItem(
        randomSource: RandomSource = RandomSource.Secure,
    ) = SelectiveDisclosureItem.fromAnyValue(
        salt = randomSource.nextBytes(32),
        claimName = null,
        claimValue = value
    )

}
