package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SingleClaimReference
import kotlin.jvm.JvmOverloads

/**
 * Which claims of a [RequestedCredential] are requested, as [JsonClaimReference]s for JSON-based credentials and
 * [MdocClaimReference]s for ISO mdocs.
 */
sealed interface ClaimSelection<C : SingleClaimReference> {

    /**
     * Requests every claim of [required], and the claims of [ifAvailable] if the holder's credential contains them. A
     * claim may occur only once in both lists together.
     *
     * Without any claim, the verifier requests no selectively disclosable claims: an SD-JWT VC is presented with only
     * the claims that are mandatory to present, a credential without selective disclosure as a whole
     * (OpenID4VP 1.0, 6.4.1).
     */
    data class All<C : SingleClaimReference> @JvmOverloads constructor(
        val required: List<C> = listOf(),
        /**
         * Claims requested only if the holder's credential contains them, as one bundle: the DCQL query offers the
         * claim combinations `[required + ifAvailable]` and, as fallback, `[required]`, in this order of preference
         * (OpenID4VP 1.0, 6.4.1), instead of the `2^n` subsets of [ifAvailable]. So if the holder's credential lacks
         * one of these claims, none of them is presented: for the required `name` and the claims `address` and
         * `email` if available, a credential without `email` is presented without `address` too.
         *
         * Whether a claim is available depends only on the claims of the holder's credential: the End-User can not
         * decline these claims, as claim combinations are "not intended to define options the End-User can choose
         * from" (OpenID4VP 1.0, 6.4.1).
         */
        val ifAvailable: List<C> = listOf(),
    ) : ClaimSelection<C> {
        init {
            claims.requireDistinct()
        }
    }
}

/** All claims of this selection, each once. */
internal val <C : SingleClaimReference> ClaimSelection<C>.claims: List<C>
    get() = when (this) {
        is ClaimSelection.All -> required + ifAvailable
    }

/**
 * Requires that no claim occurs twice, e.g. a path required and also requested if available. For an ISO mdoc, the
 * requested data elements are keys of a map (`DataElements = {+ DataElement => IntentToRetain}`,
 * ISO/IEC 18013-5:2021, 8.3.2.1.2.1), so one data element can not be requested twice.
 */
private fun List<SingleClaimReference>.requireDistinct() {
    val duplicates = groupBy { it }.filterValues { it.size > 1 }.keys
    require(duplicates.isEmpty()) { "A claim may be requested only once, but is requested more than once: $duplicates" }
}
