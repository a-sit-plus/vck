package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLJwtVcCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import com.benasher44.uuid.uuid4

data class OpenId4VpRequestOptions(
    /** Requested credentials, should be at least one. */
    override val credentials: Set<RequestOptionsCredential>,

    /** Presentation mechanism to be used for requesting credentials. */
    val presentationMechanism: PresentationMechanismEnum = PresentationMechanismEnum.PresentationExchange,

    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode],
     * by default [OpenIdConstants.ResponseMode.Fragment].
     * Setting this to any other value may require setting [responseUrl] too.
     */
    val responseMode: ResponseMode = ResponseMode.Fragment,

    /**
     * Response URL to set in the [at.asitplus.openid.AuthenticationRequestParameters.responseUrl],
     * required if [responseMode] is set to [OpenIdConstants.ResponseMode.DirectPost] or
     * [OpenIdConstants.ResponseMode.DirectPostJwt].
     */
    val responseUrl: String? = null,

    /**
     * Response type to set in [at.asitplus.openid.AuthenticationRequestParameters.responseType],
     * by default only `vp_token` (as per OpenID4VP spec, see [OpenIdConstants.VP_TOKEN]).
     * Be sure to separate values by a space, e.g. `vp_token id_token` (see [OpenIdConstants.ID_TOKEN]).
     */
    val responseType: String = VP_TOKEN,

    /** Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]. */
    override val state: String = uuid4().toString(),

    /**
     * Non-empty array of strings, where each string is a base64url-encoded JSON object that contains a typed parameter
     * set with details about the transaction that the Verifier is requesting the End-User to authorize.
     */
    val transactionData: List<TransactionData>? = null,

    /**
     * REQUIRED when signed requests defined in Appendix A.3.2 are used with the
     * Digital Credentials API(DC API). A non-empty array of strings, each string representing an Origin of the Verifier
     * that is making the request. The Wallet MUST compare values in this parameter to the Origin to detect replay of
     * the request from a malicious Verifier. If the Origin does not match any of the entries in expected_origins,
     * the Wallet MUST return an error. This error SHOULD be an invalid_request error. This parameter is not for use in
     * unsigned requests and therefore a Wallet MUST ignore this parameter if it is present in an unsigned request.
     */
    val expectedOrigins: List<String>? = null,

    /**
     * Whether the client_id should be added to the request. Required for DC API:
     * The client_id parameter MUST be omitted in unsigned requests defined in Appendix A.3.1.
     * The client_id parameter MUST be present in signed requests defined in Appendix A.3.2, as it communicates to the
     * Wallet which Client Identifier Prefix and Client Identifier to use when authenticating the client through
     * verification of the request signature or retrieving client metadata.
     */
    val populateClientId: Boolean = true,
) : RequestOptions {
    init {
        if (!transactionData.isNullOrEmpty()) {
            val transactionIds = transactionData.map { it.credentialIds.toList() }.flatten().sorted().distinct()
            val credentialIds = credentials.map { it.id }.sorted().distinct()
            require(transactionIds == credentialIds) { "OpenId4VP defines that the credential_ids that must be part of a transaction_data element have to be an ID from InputDescriptor" }
        }
        if (isAnyDcApi) {
            require(isDcql) { "DC API only supports DCQL" }
            requireNotNull(expectedOrigins) { "Expected origins must be set for DC API" }
        } else {
            require(populateClientId) { "client_id should be set for anything but (unsigned) DC API requests" }
        }
    }

    val isDcql: Boolean
        get() = presentationMechanism == PresentationMechanismEnum.DCQL

    val isPresentationExchange
        get() = presentationMechanism == PresentationMechanismEnum.PresentationExchange

    val isAnyDirectPost: Boolean
        get() = (responseMode == ResponseMode.DirectPost) ||
                (responseMode == ResponseMode.DirectPostJwt)

    val isAnyDcApi: Boolean
        get() = responseMode == ResponseMode.DcApi || responseMode == ResponseMode.DcApiJwt

    val isSiop: Boolean
        get() = responseType.contains(OpenIdConstants.ID_TOKEN)

    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")

    fun toDCQLQuery(): DCQLQuery? =
        if (credentials.isEmpty()) null
        else DCQLQuery(
            credentials = DCQLCredentialQueryList(
                credentials.mapNotNull { it.toQuery() }.takeIf { it.isNotEmpty() }?.toNonEmptyList()
                    ?: return null
            ),
        )

    private fun RequestOptionsCredential.toQuery(): DCQLCredentialQuery? = when (representation) {
        CredentialRepresentation.PLAIN_JWT -> toJwtVcQuery()
        CredentialRepresentation.SD_JWT -> toSdJwtQuery()
        CredentialRepresentation.ISO_MDOC -> toIsoMdocQuery()
    }

    // TODO: how to properly handle non-required claims?
    private fun RequestOptionsCredential.nonOptionalAndOptionalRequestedAttributes(): List<Pair<String, Boolean>> =
        (requestedAttributes?.map { it to true } ?: listOf()) +
                (requestedOptionalAttributes?.map { it to false } ?: listOf())

    private fun RequestOptionsCredential.toJwtVcQuery() = credentialScheme.vcType?.let { vcType ->
        DCQLJwtVcCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(
                    listOfNotNull(vcType)
                )
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attribute, _) ->
                    DCQLJsonClaimsQuery(path = attribute.splitByDotToDcqlPath())
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    private fun RequestOptionsCredential.toSdJwtQuery() = credentialScheme.sdJwtType?.let { sdJwtType ->
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf(sdJwtType)
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attribute, _) ->
                    DCQLJsonClaimsQuery(path = attribute.splitByDotToDcqlPath())
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    private fun RequestOptionsCredential.toIsoMdocQuery() = credentialScheme.isoDocType?.let { isoDocType ->
        DCQLIsoMdocCredentialQuery(
            id = DCQLCredentialQueryIdentifier(id),
            meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = isoDocType
            ),
            claims = nonOptionalAndOptionalRequestedAttributes()
                .takeIf { it.isNotEmpty() } // requesting all claims if none are specified
                ?.map { (attribute, _) ->
                    DCQLIsoMdocClaimsQuery(
                        path = DCQLClaimsPathPointer(credentialScheme.isoNamespace!!, attribute)
                    )
                }?.toNonEmptyList()
                ?.let { DCQLClaimsQueryList(it) }
        )
    }

    private fun String.splitByDotToDcqlPath() = DCQLClaimsPathPointer(
        split(".").map { DCQLClaimsPathPointerSegment.NameSegment(it) }.toNonEmptyList()
    )

    fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
    ): PresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = toInputDescriptor(containerJwt, containerSdJwt)
    )

    fun toInputDescriptor(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
    ): List<InputDescriptor> = credentials.map {
        DifInputDescriptor(
            id = it.buildId(),
            format = it.toFormatHolder(containerJwt, containerSdJwt),
            constraints = it.toConstraint(),
        )
    }
}

