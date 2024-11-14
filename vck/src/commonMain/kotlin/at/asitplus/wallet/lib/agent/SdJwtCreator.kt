package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlin.random.Random

/**
 * See [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html#name-simple-structured-sd-jwt)
 */
object SdJwtCreator {

    /**
     * Creates a JSON object to contain only digests for the selectively disclosable claims, and the plain values for
     * other claims that are not selectively disclosable (see [ClaimToBeIssued.selectivelyDisclosable])
     *
     * @return The encoded JSON object and the disclosure strings
     */
    fun Collection<ClaimToBeIssued>.toSdJsonObject(): Pair<JsonObject, Collection<String>> =
        mutableListOf<String>().let { disclosures ->
            buildJsonObject {
                with(partition { it.value is Collection<*> && it.value.first() is ClaimToBeIssued }) {
                    val objectClaimDigests = first.mapNotNull { claim ->
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
                    val singleClaimsDigests = second.mapNotNull { claim ->
                        if (claim.selectivelyDisclosable) {
                            claim.toSdItem().toDisclosure()
                                .also { disclosures.add(it) }
                                .hashDisclosure()
                        } else {
                            put(claim.name, claim.value.toJsonElement())
                            null
                        }
                    }
                    (objectClaimDigests + singleClaimsDigests).let { digests ->
                        if (digests.isNotEmpty())
                            putJsonArray("_sd") { addAll(digests) }
                    }
                }
            } to disclosures
        }

    private fun ClaimToBeIssued.toSdItem(claimValue: JsonObject) =
        SelectiveDisclosureItem(Random.nextBytes(32), name, claimValue)

    private fun ClaimToBeIssued.toSdItem() =
        SelectiveDisclosureItem(Random.nextBytes(32), name, value)

}