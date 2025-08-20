package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.dif.RequirementEnum
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryInstance
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import com.benasher44.uuid.uuid4
import kotlinx.serialization.json.JsonPrimitive

@Deprecated("Will be removed in future release", replaceWith= ReplaceWith("RequestOptions"))
typealias OpenIdRequestOptions = RequestOptions

// TODO Should be NormalizedJsonPath
typealias RequestedAttributes = Set<String>

data class RequestOptions(
    /** Requested credentials, should be at least one. */
    val credentials: Set<RequestOptionsCredential>,

    /** Presentation mechanism to be used for requesting credentials. */
    val presentationMechanism: PresentationMechanismEnum = PresentationMechanismEnum.PresentationExchange,

    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode],
     * by default [OpenIdConstants.ResponseMode.Fragment].
     * Setting this to any other value may require setting [responseUrl] too.
     */
    val responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,

    /**
     * Response URL to set in the [AuthenticationRequestParameters.responseUrl],
     * required if [responseMode] is set to [OpenIdConstants.ResponseMode.DirectPost] or
     * [OpenIdConstants.ResponseMode.DirectPostJwt].
     */
    val responseUrl: String? = null,

    /**
     * Response type to set in [AuthenticationRequestParameters.responseType],
     * by default only `vp_token` (as per OpenID4VP spec, see [OpenIdConstants.VP_TOKEN]).
     * Be sure to separate values by a space, e.g. `vp_token id_token` (see [OpenIdConstants.ID_TOKEN]).
     */
    val responseType: String = VP_TOKEN,

    /** Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]. */
    val state: String = uuid4().toString(),

    /**
     * Optional URL to include metadata by reference (see [AuthenticationRequestParameters.clientMetadataUri])
     * instead of by value (see [AuthenticationRequestParameters.clientMetadata])
     */
    val clientMetadataUrl: String? = null,

    /**
     * Set this value to include metadata with encryption parameters set. Beware if setting this value and also
     * [clientMetadataUrl], that the URL shall point to [OpenId4VpVerifier.metadataWithEncryption].
     */
    val encryption: Boolean = false,

    /**
     *  Non-empty array of strings, where each string is a base64url-encoded JSON object that contains a typed parameter set
     *  with details about the transaction that the Verifier is requesting the End-User to authorize.
     */
    val transactionData: List<TransactionData>? = null,
) {
    init {
        if (!transactionData.isNullOrEmpty()) {
            val transactionIds =
                transactionData.mapNotNull { it.credentialIds?.toList() }.flatten()?.sorted()?.distinct()
            val credentialIds = credentials.map { it.id }.sorted().distinct()
            transactionIds?.let {
                require(it == credentialIds) { "OpenId4VP defines that the credential_ids that must be part of a transaction_data element have to be an ID from InputDescriptor" }
            }
        }
    }

    val isDcql: Boolean
        get() = presentationMechanism == PresentationMechanismEnum.DCQL

    val isPresentationExchange
        get() = presentationMechanism == PresentationMechanismEnum.PresentationExchange

    val isAnyDirectPost: Boolean
        get() = (responseMode == OpenIdConstants.ResponseMode.DirectPost) ||
                (responseMode == OpenIdConstants.ResponseMode.DirectPostJwt)

    val isSiop: Boolean
        get() = responseType.contains(OpenIdConstants.ID_TOKEN)

    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")

    fun toDCQLQuery(): DCQLQuery? = if (credentials.isEmpty()) null else DCQLQuery(
        credentials = DCQLCredentialQueryList<DCQLCredentialQueryInstance>(
            credentials.map<RequestOptionsCredential, DCQLCredentialQueryInstance> { credential ->
                val format = when (credential.representation) {
                    CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
                    CredentialRepresentation.SD_JWT -> CredentialFormatEnum.DC_SD_JWT
                    CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
                }
                val meta = when (credential.representation) {
                    CredentialRepresentation.PLAIN_JWT -> null
                    CredentialRepresentation.SD_JWT -> DCQLSdJwtCredentialMetadataAndValidityConstraints(
                        vctValues = listOf(credential.credentialScheme.sdJwtType!!)
                    )

                    CredentialRepresentation.ISO_MDOC -> DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                        doctypeValue = credential.credentialScheme.isoDocType!!
                    )
                }
                val requestedAttributes = (credential.requestedAttributes?.map {
                    it to true
                } ?: listOf()) + (credential.requestedOptionalAttributes?.map {
                    it to false
                } ?: listOf())

                val claims = requestedAttributes.map { (attribute, isRequired) ->
                    // TODO: how to properly handle non-required claims?
                    when (credential.representation) {
                        CredentialRepresentation.SD_JWT,
                        CredentialRepresentation.PLAIN_JWT,
                            -> DCQLJsonClaimsQuery(
                            path = splitByDotToDcqlPath(attribute)
                        )

                        CredentialRepresentation.ISO_MDOC -> DCQLIsoMdocClaimsQuery(
                            namespace = credential.credentialScheme.isoNamespace!!,
                            claimName = attribute,
                            path = DCQLClaimsPathPointer(credential.credentialScheme.isoNamespace!!, attribute)
                        )
                    }
                }.ifEmpty {
                    null // requesting all claims if none are specified
                }?.toNonEmptyList()?.let {
                    DCQLClaimsQueryList(it)
                }

                DCQLCredentialQueryInstance(
                    id = DCQLCredentialQueryIdentifier(credential.id),
                    format = format,
                    meta = meta,
                    claims = claims,
                )
            }.toNonEmptyList()
        ),
    )

    private fun splitByDotToDcqlPath(attribute: String) = DCQLClaimsPathPointer(
        attribute.split(".").map { DCQLClaimsPathPointerSegment.NameSegment(it) }.toNonEmptyList()
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

data class RequestOptionsCredential(
    /** Credential type to request, or `null` to make no restrictions. */
    val credentialScheme: ConstantIndex.CredentialScheme,
    /** Required representation, see [ConstantIndex.CredentialRepresentation]. */
    val representation: CredentialRepresentation = CredentialRepresentation.PLAIN_JWT,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions.
     *
     * **By convention, strings containing a `.` are assumed to request nested claims**
     *
     * Use the claim names `name` and `address.formatted` to request all claims within this credential:
     * ````
     *   "name": "Mustermann",
     *   "address": {
     *      "formatted": "Herrengasse 1"
     *   }
     * ```
     */
    val requestedAttributes: RequestedAttributes? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional), or `null` to make no restrictions.
     *
     * **By convention, strings containing a `.` are assumed to request nested claims**
     *
     * Use the claim names `name` and `address.formatted` to request all claims within this credential:
     * ````
     *   "name": "Mustermann",
     *   "address": {
     *      "formatted": "Herrengasse 1"
     *   }
     * ```
     */
    val requestedOptionalAttributes: RequestedAttributes? = null,
    /** ID to be used in [DifInputDescriptor] or [QesInputDescriptor], or [DCQLCredentialQueryInstance] */
    val id: String = uuid4().toString(),
) {
    fun buildId() = if (isMdoc) credentialScheme.isoDocType!! else id

    private val isMdoc: Boolean
        get() = credentialScheme.isoDocType != null && representation == CredentialRepresentation.ISO_MDOC

    fun toConstraint() =
        Constraint(
            limitDisclosure = if (isMdoc) RequirementEnum.REQUIRED else null,
            fields = (requiredAttributes() + optionalAttributes() + toTypeConstraint()).filterNotNull().toSet()
        )

    private fun requiredAttributes() = requestedAttributes?.createConstraints(credentialScheme, false)
        ?: listOf()

    private fun optionalAttributes() = requestedOptionalAttributes?.createConstraints(credentialScheme, true)
        ?: listOf()

    private fun toTypeConstraint() = when (representation) {
        CredentialRepresentation.PLAIN_JWT -> credentialScheme.toVcConstraint()
        CredentialRepresentation.SD_JWT -> credentialScheme.toSdJwtConstraint()
        CredentialRepresentation.ISO_MDOC -> null
    }

    fun toFormatHolder(containerJwt: FormatContainerJwt, containerSdJwt: FormatContainerSdJwt) =
        when (representation) {
            CredentialRepresentation.PLAIN_JWT -> FormatHolder(jwtVp = containerJwt)
            CredentialRepresentation.SD_JWT -> FormatHolder(jwtSd = containerSdJwt, sdJwt = containerSdJwt)
            CredentialRepresentation.ISO_MDOC -> FormatHolder(msoMdoc = containerJwt)
        }

    private fun RequestedAttributes.createConstraints(
        scheme: ConstantIndex.CredentialScheme?,
        optional: Boolean,
    ): Collection<ConstraintField> = map {
        if (isMdoc) it.toIsoMdocConstraintField(scheme, optional) else it.toJwtConstraintField(optional)
    }

    private fun String.toIsoMdocConstraintField(scheme: ConstantIndex.CredentialScheme?, optional: Boolean) =
        ConstraintField(
            path = listOf(scheme.prefixWithIsoNamespace(this)),
            intentToRetain = false,
            optional = optional
        )

    private fun String.toJwtConstraintField(optional: Boolean): ConstraintField =
        ConstraintField(path = listOf(splitByDotToJsonPath()), optional = optional)

    // EUDIW Reference Implementation only supports dot notation for JSONPath
    private fun String.splitByDotToJsonPath(): String =
        NormalizedJsonPath(split(".").map { NameSegment(it) }).toShorthandNameSegmentNotation()

    private fun ConstantIndex.CredentialScheme?.prefixWithIsoNamespace(attribute: String): String =
        NormalizedJsonPath(
            NameSegment(this?.isoNamespace ?: "mdoc"),
            NameSegment(attribute),
        ).toString()

    private fun ConstantIndex.CredentialScheme.toVcConstraint() = if (supportsVcJwt)
        ConstraintField(
            path = listOf("$.type"),
            filter = ConstraintFilter(
                type = "string",
                const = JsonPrimitive(vcType),
            )
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtConstraint() = if (supportsSdJwt)
        ConstraintField(
            path = listOf("$.vct"),
            filter = ConstraintFilter(
                type = "string",
                const = JsonPrimitive(sdJwtType!!)
            )
        ) else null
}
