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
     * All claims of this selection, in the order of their first occurrence: the claims queries in `claims` of a DCQL
     * Credential Query (OpenID4VP 1.0, 6.1), which its claim combinations reference.
     */
    val allClaims: Set<C>

    /**
     * Requests every claim of [required], and the claims of [ifAvailable] if the holder's credential contains them. A
     * claim may not be both required and requested if available.
     *
     * Without any claim, the verifier requests no selectively disclosable claims: an SD-JWT VC is presented with only
     * the claims that are mandatory to present, a credential without selective disclosure as a whole
     * (OpenID4VP 1.0, 6.4.1).
     */
    data class All<C : SingleClaimReference> @JvmOverloads constructor(
        val required: Set<C> = setOf(),
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
        val ifAvailable: Set<C> = setOf(),
    ) : ClaimSelection<C> {
        override val allClaims: Set<C>
            get() = required + ifAvailable

        init {
            requireDisjoint(required, ifAvailable)
        }
    }

    /**
     * Requests the claims of [common] and of exactly one of the [options], which are alternative claim combinations
     * in the order of the verifier's preference: the DCQL query offers one claim combination per option, `common`
     * plus that option (OpenID4VP 1.0, 6.4.1). The wallet "SHOULD return the first option that it can satisfy", and
     * the verifier accepts any of them. E.g. `options = [[age_over_18], [birth_date]]` prefers `age_over_18` and
     * accepts `birth_date`, following the "principle of least information disclosure" (OpenID4VP 1.0, 6.4.1).
     *
     * Which option is presented depends on the claims of the holder's credential, not on a choice of the End-User:
     * claim combinations are "not intended to define options the End-User can choose from" (OpenID4VP 1.0, 6.4.1).
     * If the holder's credential satisfies none of the options, it is not presented.
     *
     * At least one option is required. An option may be empty, accepting the credential with only the [common]
     * claims, but some claim must be requested; use [All] without claims to request none. A claim of [common] may
     * not occur in an option, while one claim may occur in several options. The [options] are a list, as their order
     * is the verifier's preference.
     */
    data class Alternatives<C : SingleClaimReference> @JvmOverloads constructor(
        val options: List<Set<C>>,
        val common: Set<C> = setOf(),
    ) : ClaimSelection<C> {

        /** Requests the claims of [common] and of exactly one of the [options], see [Alternatives]. */
        @JvmOverloads
        constructor(vararg options: Set<C>, common: Set<C> = setOf()) : this(options.toList(), common)

        override val allClaims: Set<C>
            get() = common + options.flatten()

        init {
            require(options.isNotEmpty()) { "At least one option of claims is required" }
            require(allClaims.isNotEmpty()) { "Alternatives without any claim request none; use All() instead" }
            options.forEach { requireDisjoint(common, it) }
        }
    }
}

/**
 * Requires that no claim occurs in both parts of one claim combination, e.g. a path required and also requested if
 * available, or in the common claims and an option. For an ISO mdoc, the requested data elements are keys of a map
 * (`DataElements = {+ DataElement => IntentToRetain}`, ISO/IEC 18013-5:2021, 8.3.2.1.2.1), so one data element can not
 * be requested twice.
 */
private fun requireDisjoint(first: Set<SingleClaimReference>, second: Set<SingleClaimReference>) {
    val duplicates = first intersect second
    require(duplicates.isEmpty()) { "A claim may be requested only once, but is requested more than once: $duplicates" }
}
