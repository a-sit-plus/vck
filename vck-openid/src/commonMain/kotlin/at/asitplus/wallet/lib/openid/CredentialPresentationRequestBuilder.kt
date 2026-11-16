package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQuery
import at.asitplus.openid.dcql.DCQLClaimsQueryIdentifier
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLCredentialSetQuery
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLJwtVcCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedCredentialSet
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.IsoDeviceRetrieval
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SingleClaimReference
import io.github.z4kn4fein.semver.Version
import kotlin.jvm.JvmStatic

/**
 * Builds a [CredentialPresentationRequest] from the credentials of a [RequestedPresentation],
 * to be used in [OpenId4VpRequestOptions]: a DCQL query (OpenID4VP 1.0, 6) with [toDCQLRequest],
 * or an ISO `DeviceRequest` (ISO/IEC 18013-5:2021, 8.3.2.1.2.1) with [toIsoDeviceRetrievalRequest].
 */
class CredentialPresentationRequestBuilder(
    val presentation: RequestedPresentation,
) {
    /** Requests every one of [credentials], see [RequestedPresentation.allOf]. */
    constructor(credentials: Collection<RequestedCredential>) :
            this(RequestedPresentation.allOf(*credentials.toTypedArray()))

    /** Requests every one of [credentials], see [RequestedPresentation.allOf]. */
    constructor(vararg credentials: RequestedCredential) :
            this(RequestedPresentation.allOf(*credentials))

    /** Requests every one of [credentials], see [RequestOptionsCredential.toRequestedCredential]. */
    @Deprecated(
        "Request RequestedCredentials",
        ReplaceWith("CredentialPresentationRequestBuilder(credentials.map { it.toRequestedCredential() })"),
    )
    @Suppress("DEPRECATION")
    constructor(vararg credentials: RequestOptionsCredential) :
            this(credentials.map { it.toRequestedCredential() })

    /**
     * The DCQL query of [presentation]: one Credential Query per credential (OpenID4VP 1.0, 6.1),
     * and one Credential Set Query per set (OpenID4VP 1.0, 6.2), omitted if every credential is required,
     * which is what an absent `credential_sets` requests (OpenID4VP 1.0, 6.4.2).
     */
    fun toDCQLRequest() = DCQLRequest(
        DCQLQuery(
            credentials = presentation.toCredentialQueryList(),
            credentialSets = presentation.toCredentialSets(),
        )
    )

    private fun RequestedPresentation.toCredentialSets() =
        if (requiresEveryCredential) null else sets.map { it.toCredentialSetQuery() }.toNonEmptyList()

    private fun RequestedCredentialSet.toCredentialSetQuery() = DCQLCredentialSetQuery(
        options = options.map { it.map { DCQLCredentialQueryIdentifier(it.id) } }.toNonEmptyList(),
        required = required,
    )

    private fun RequestedPresentation.toCredentialQueryList() =
        DCQLCredentialQueryList(credentials.map { it.toQuery() }.toNonEmptyList())

    /**
     * The ISO `DeviceRequest` of [presentation],
     * with one `DocRequest` per credential, see [RequestedCredential.Mdoc.toDocRequest].
     *
     * Fails for other credentials than ISO mdocs, and if not every credential is required, as a `DeviceRequest`
     * requests every one of its `DocRequests` (ISO/IEC 18013-5:2021, 8.3.2.1.2.1), instead of silently requesting
     * alternative or optional credentials.
     */
    fun toIsoDeviceRetrievalRequest(): IsoDeviceRetrieval {
        require(presentation.requiresEveryCredential) {
            "An ISO DeviceRequest requests every credential, but some are alternative or optional"
        }
        val docRequests = presentation.credentials.map {
            require(it is RequestedCredential.Mdoc) { "An ISO DeviceRequest requests only mdocs, but not $it" }
            it.toDocRequest()
        }
        return IsoDeviceRetrieval(
            deviceRequest = DeviceRequest(
                parsedVersion = Version(1, 0),
                docRequests = docRequests.toTypedArray(),
                deviceRequestInfo = null,
                readerAuthAll = null,
            )
        )
    }

    companion object {
        /** Requests every one of [credentials], see [RequestOptionsCredential.toRequestedCredential]. */
        @Deprecated(
            "Request RequestedCredentials",
            ReplaceWith("CredentialPresentationRequestBuilder(credentials.map { it.toRequestedCredential() })"),
        )
        @JvmStatic
        @Suppress("DEPRECATION")
        fun fromRequestOptions(credentials: Collection<RequestOptionsCredential>) =
            CredentialPresentationRequestBuilder(credentials.map { it.toRequestedCredential() })
    }
}

/** Whether every credential is required: every set is required and has a single option. */
private val RequestedPresentation.requiresEveryCredential: Boolean
    get() = sets.all { it.required && it.options.size == 1 }

private fun RequestedCredential.toQuery(): DCQLCredentialQuery = when (this) {
    is RequestedCredential.SdJwt -> toSdJwtQuery(claims.toJsonClaimsQueries())
    is RequestedCredential.VcJwt -> toVcJwtQuery(claims.toJsonClaimsQueries())
    is RequestedCredential.Mdoc -> toIsoMdocQuery(claims.toMdocClaimsQueries(intentToRetain))
}

private fun RequestedCredential.SdJwt.toSdJwtQuery(
    queries: ClaimsQueries<DCQLJsonClaimsQuery>
) = DCQLSdJwtCredentialQuery(
    id = DCQLCredentialQueryIdentifier(id),
    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(vct)),
    claims = queries.claims,
    claimSets = queries.claimSets,
)

private fun RequestedCredential.VcJwt.toVcJwtQuery(
    queries: ClaimsQueries<DCQLJsonClaimsQuery>
) = DCQLJwtVcCredentialQuery(
    id = DCQLCredentialQueryIdentifier(id),
    meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(typeValues = nonEmptyListOf(listOf(type))),
    claims = queries.claims,
    claimSets = queries.claimSets,
)

private fun RequestedCredential.Mdoc.toIsoMdocQuery(
    queries: ClaimsQueries<DCQLIsoMdocClaimsQuery>
) = DCQLIsoMdocCredentialQuery(
    id = DCQLCredentialQueryIdentifier(id),
    meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(doctypeValue = docType),
    claims = queries.claims,
    claimSets = queries.claimSets,
)

private fun ClaimSelection<JsonClaimReference>.toJsonClaimsQueries() =
    toClaimsQueries { claim, id -> DCQLJsonClaimsQuery(id = id, path = claim.path) }

private fun ClaimSelection<MdocClaimReference>.toMdocClaimsQueries(intentToRetain: Set<MdocClaimReference>) =
    toClaimsQueries { claim, id ->
        DCQLIsoMdocClaimsQuery(
            id = id,
            path = DCQLClaimsPathPointer(claim.namespace, claim.claimName),
            intentToRetain = if (claim in intentToRetain) true else null,
        )
    }

/** The `claims` and `claim_sets` of a DCQL Credential Query (OpenID4VP 1.0, 6.1). */
private class ClaimsQueries<Q : DCQLClaimsQuery>(
    val claims: DCQLClaimsQueryList<Q>?,
    val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>?,
)

/**
 * The claims queries of this selection, one per claim of [ClaimSelection.allClaims],
 * and its claim combinations as `claim_sets` (OpenID4VP 1.0, 6.4.1):
 * none for [ClaimSelection.All] without claims requested if available, as all listed claims are requested then,
 * otherwise one per combination, in the order of preference.
 * The claims queries get IDs, their index, only if there are claim combinations,
 * as an ID is "REQUIRED if `claim_sets` is present" (OpenID4VP 1.0, 6.3).
 * Without any claim, `claims` is absent, which requests the claims that are mandatory to present.
 */
private fun <C : SingleClaimReference, Q : DCQLClaimsQuery> ClaimSelection<C>.toClaimsQueries(
    toQuery: (claim: C, id: DCQLClaimsQueryIdentifier?) -> Q,
): ClaimsQueries<Q> {
    val combinations = when (this) {
        is ClaimSelection.All -> if (ifAvailable.isEmpty()) null else listOf(required + ifAvailable, required)
        is ClaimSelection.Alternatives -> options.map { common + it }
    }
    if (allClaims.isEmpty())
        return ClaimsQueries(claims = null, claimSets = null)
    if (combinations == null) {
        return ClaimsQueries(DCQLClaimsQueryList(allClaims.map { toQuery(it, null) }.toNonEmptyList()), null)
    }
    val ids = allClaims.withIndex().associate {
        it.value to DCQLClaimsQueryIdentifier(it.index.toString())
    }
    return ClaimsQueries(
        claims = DCQLClaimsQueryList(allClaims.map { toQuery(it, ids.getValue(it)) }.toNonEmptyList()),
        claimSets = combinations.map { combination -> combination.map { ids.getValue(it) } }.toNonEmptyList(),
    )
}
