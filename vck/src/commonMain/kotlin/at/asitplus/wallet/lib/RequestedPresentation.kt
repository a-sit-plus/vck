package at.asitplus.wallet.lib

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.UseCase
import at.asitplus.iso.forUseCases
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * The credentials a verifier requests in one presentation request, as [sets] of alternative credential combinations
 * (OpenID4VP 1.0, 6.4.2): every required set has to be satisfied by one of its options, optional sets may be.
 *
 * Fails without any set, without a required set, as optional sets alone are satisfied by presenting nothing, and for
 * two different credentials sharing one [RequestedCredential.id], as "within the Authorization Request, the same `id`
 * MUST NOT be present more than once" (OpenID4VP 1.0, 6.1). The same credential may occur in several options and
 * sets; it is requested by one Credential Query.
 */
data class RequestedPresentation(
    val sets: List<RequestedCredentialSet>,
) {
    /** Requests the credentials of [sets], see [RequestedPresentation]. */
    constructor(vararg sets: RequestedCredentialSet) : this(sets.toList())

    /**
     * The credentials of all [sets], each once, in the order of their first occurrence:
     * the Credential Queries in `credentials` of the DCQL query (OpenID4VP 1.0, 6).
     */
    val credentials: Set<RequestedCredential> = sets.flatMap { set -> set.options.flatten() }.toSet()

    init {
        require(sets.isNotEmpty()) { "At least one set of credentials is required" }
        require(sets.any { it.required }) {
            "At least one set of credentials has to be required, as optional sets alone are satisfied by nothing"
        }
        val sharedIds = credentials.groupBy { it.id }.filterValues { it.size > 1 }.keys
        require(sharedIds.isEmpty()) { "Different credentials share the IDs $sharedIds" }
    }

    /**
     * The ISO/IEC 18013-5 `DeviceRequest` of this presentation, e.g. for ISO/IEC 18013-7 Annex C: one `DocRequest` per
     * credential of [credentials], see [RequestedCredential.Mdoc.toDocRequest], and one use case per set, with its
     * [RequestedCredentialSet.purposeHints], see `DeviceRequest.forUseCases` (ISO/IEC DIS 18013-5:2026, 10.2.5).
     * Without anything a use case would add to "every document request is required", the request has version 1.0.
     *
     * Fails for other credentials than ISO mdocs, and for a set with an option contained in another one, e.g.
     * `[pid, mdl]` and `[pid]`, which ISO can not satisfy, see `DeviceRequest.forUseCases`: request a required set
     * `[pid]` and an optional set `[mdl]` instead.
     */
    fun toDeviceRequest(): DeviceRequest {
        val docRequests = credentials.map {
            require(it is RequestedCredential.Mdoc) { "An ISO DeviceRequest requests only mdocs, but not $it" }
            it.toDocRequest()
        }
        val positions = credentials.withIndex().associate { it.value to it.index.toUInt() }
        val useCases = sets.map { set ->
            UseCase(
                mandatory = set.required,
                documentSets = set.options.map { option -> option.map { positions.getValue(it) } },
                purposeHints = set.purposeHints.ifEmpty { null },
            )
        }
        return DeviceRequest.forUseCases(docRequests = docRequests, useCases = useCases)
    }

    companion object {
        /** Requests every one of [credentials], as one required set with one option. */
        @JvmStatic
        fun allOf(vararg credentials: RequestedCredential): RequestedPresentation {
            require(credentials.isNotEmpty()) { "At least one credential is required" }
            return RequestedPresentation(RequestedCredentialSet.oneOf(credentials.toSet()))
        }
    }
}

/**
 * A set of credentials satisfying one use case of the verifier, as alternative [options], each a combination of
 * credentials to present together: a Credential Set Query of DCQL (OpenID4VP 1.0, 6.2), whose `options` are "a
 * non-empty array", and "the value of each element in the `options` array is a non-empty array of identifiers".
 *
 * Unlike claim alternatives, the options have no specified order of preference, and the wallet "typically" lets the
 * End-User choose between them (OpenID4VP 1.0, 6.4.3). Still, [options] is a list: the default submission of VC-K's
 * holder (`HolderDCQLQueryMatchingResult.toDefaultSubmission`) presents the first option it can satisfy. So for the
 * options `[pid, mdl]` and `[pid]`, it presents both credentials if the holder has an mDL, and the PID alone
 * otherwise; in the order `[pid]`, `[pid, mdl]`, it presents the PID alone.
 * Over ISO, such options can not be requested at all, see [RequestedPresentation.toDeviceRequest].
 */
data class RequestedCredentialSet @JvmOverloads constructor(
    val options: List<Set<RequestedCredential>>,
    /**
     * Whether this set has to be satisfied; if not, the wallet may present it (OpenID4VP 1.0, 6.4.2). The default
     * submission of VC-K's holder (`HolderDCQLQueryMatchingResult.toDefaultSubmission`) presents only required sets: a
     * wallet that offers an optional set to the End-User shows `HolderDCQLQueryMatchingResult.credentialSets` and
     * builds the submission of the chosen options with `HolderDCQLQueryMatchingResult.toSubmission`.
     */
    val required: Boolean = true,
    /**
     * Purpose codes of this set by the ID of the entity that defines them, the `PurposeHints` of its ISO use case, to
     * "help the user to distinguish the different UseCase in the request", e.g. `UseCase.PURPOSE_AGE_VERIFICATION` of
     * `UseCase.PURPOSE_CONTROLLER_ISO` (ISO/IEC DIS 18013-5:2026, 10.2.5).
     * *Not sent over OpenID4VP, whose Credential Set Query has no purpose (OpenID4VP 1.0, 6.2).*
     */
    val purposeHints: Map<String, Int> = mapOf(),
) {
    init {
        require(options.isNotEmpty()) { "At least one option of credentials is required" }
        val emptyOptions = options.indices.filter { options[it].isEmpty() }
        require(emptyOptions.isEmpty()) {
            "Every option needs at least one credential, but the options at $emptyOptions are empty"
        }
    }

    companion object {
        /** A required set, satisfied by one of the [options]. */
        @JvmStatic
        fun oneOf(vararg options: Set<RequestedCredential>) = RequestedCredentialSet(options.toList(), required = true)

        /**
         * A required set, satisfied by one of the [options], see [oneOf]; for Java, which warns about the unchecked
         * generic array of the vararg overload.
         */
        @JvmStatic
        fun oneOf(options: List<Set<RequestedCredential>>) = RequestedCredentialSet(options, required = true)

        /** An optional set, which the wallet may satisfy by one of the [options]. */
        @JvmStatic
        fun optional(vararg options: Set<RequestedCredential>) =
            RequestedCredentialSet(options.toList(), required = false)

        /**
         * An optional set, which the wallet may satisfy by one of the [options], see [optional]; for Java, which warns
         * about the unchecked generic array of the vararg overload.
         */
        @JvmStatic
        fun optional(options: List<Set<RequestedCredential>>) = RequestedCredentialSet(options, required = false)
    }
}
