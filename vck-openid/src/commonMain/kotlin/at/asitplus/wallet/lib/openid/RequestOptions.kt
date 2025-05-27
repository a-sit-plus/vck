package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.*
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.IndexSegment
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.*
import at.asitplus.wallet.lib.agent.PresentationRequestParameters.Flow
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import com.benasher44.uuid.uuid4
import kotlinx.serialization.json.JsonPrimitive

// TODO Should be NormalizedJsonPath
typealias RequestedAttributes = Set<String>

interface RequestOptions {
    /** Requested credentials, should be at least one. */
    val credentials: Set<RequestOptionsCredential>

    /** Presentation mechanism to be used for requesting credentials. */
    val presentationMechanism: PresentationMechanismEnum

    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode],
     * by default [OpenIdConstants.ResponseMode.Fragment].
     * Setting this to any other value may require setting [responseUrl] too.
     */
    val responseMode: OpenIdConstants.ResponseMode

    /**
     * Response URL to set in the [AuthenticationRequestParameters.responseUrl],
     * required if [responseMode] is set to [OpenIdConstants.ResponseMode.DirectPost] or
     * [OpenIdConstants.ResponseMode.DirectPostJwt].
     */
    val responseUrl: String?

    /**
     * Response type to set in [AuthenticationRequestParameters.responseType],
     * by default only `vp_token` (as per OpenID4VP spec, see [OpenIdConstants.VP_TOKEN]).
     * Be sure to separate values by a space, e.g. `vp_token id_token` (see [OpenIdConstants.ID_TOKEN]).
     */
    val responseType: String

    /** Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]. */
    val state: String

    /**
     * Optional URL to include metadata by reference (see [AuthenticationRequestParameters.clientMetadataUri])
     * instead of by value (see [AuthenticationRequestParameters.clientMetadata])
     */
    val clientMetadataUrl: String?

    /**
     * Set this value to include metadata with encryption parameters set. Beware if setting this value and also
     * [clientMetadataUrl], that the URL shall point to [OpenId4VpVerifier.metadataWithEncryption].
     */
    val encryption: Boolean

    val isAnyDirectPost: Boolean
        get() = (responseMode == OpenIdConstants.ResponseMode.DirectPost) ||
                (responseMode == OpenIdConstants.ResponseMode.DirectPostJwt)

    val isSiop: Boolean
        get() = responseType.contains(OpenIdConstants.ID_TOKEN)

    val isDcql: Boolean
        get() = presentationMechanism == PresentationMechanismEnum.DCQL

    val isPresentationExchange
        get() = presentationMechanism == PresentationMechanismEnum.PresentationExchange

    val transactionData: List<TransactionData>?

    /**
     * [rqesFlow] is used to decide where transaction data is encoded:
     * [Flow.UC5] for UC5 compliant,
     * [Flow.OID4VP] for OID compliant
     * and null for both
     */
    val rqesFlow: Flow?

    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")

    fun toDCQLQuery(): DCQLQuery?

    fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
        flow: Flow? = null,
    ): PresentationDefinition?

    fun toInputDescriptor(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
        flow: Flow? = null,
    ): List<InputDescriptor>
}

data class OpenIdRequestOptions(
    override val credentials: Set<RequestOptionsCredential>,
    override val responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
    override val responseUrl: String? = null,
    override val responseType: String = VP_TOKEN,
    override val state: String = uuid4().toString(),
    override val clientMetadataUrl: String? = null,
    override val encryption: Boolean = false,
    override val presentationMechanism: PresentationMechanismEnum = PresentationMechanismEnum.PresentationExchange,
    override val transactionData: List<TransactionData>? = null,
    override val rqesFlow: Flow? = null,
) : RequestOptions {

    override fun toDCQLQuery(): DCQLQuery? = if (credentials.isEmpty()) null else DCQLQuery(
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

    override fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
        flow: Flow?,
    ): PresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = toInputDescriptor(containerJwt, containerSdJwt, flow)
    )

    override fun toInputDescriptor(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
        flow: Flow?,
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
        ConstraintField(path = listOf(scheme.prefixWithIsoNamespace(this)), intentToRetain = false, optional = optional)

    private fun String.toJwtConstraintField(optional: Boolean): ConstraintField =
        ConstraintField(path = listOf(splitByDotToJsonPath()), optional = optional)

    // EUDIW Reference Implementation only supports dot notation for JSONPath
    private fun String.splitByDotToJsonPath(): String =
        NormalizedJsonPath(split(".").map { NameSegment(it) }).toDotNotation()

    private fun NormalizedJsonPath.toDotNotation(): String =
        "$" + segments.joinToString("") { it.toDotNotation() }

    private fun NormalizedJsonPathSegment.toDotNotation(): CharSequence = when (this) {
        is IndexSegment -> toString()
        is NameSegment -> if (memberName.isValidForDotNotation()) ".$memberName" else toString()
    }

    private fun String.isValidForDotNotation(): Boolean =
        firstOrNull().isLetterOrUnderscore() && all { it.isLetterOrDigit() || it.isUnderscore() }

    private fun Char?.isLetterOrUnderscore(): Boolean = if (this == null) false else (isLetter() || this.isUnderscore())

    private fun Char.isUnderscore(): Boolean = this == '_'

    private fun ConstantIndex.CredentialScheme?.prefixWithIsoNamespace(attribute: String): String = NormalizedJsonPath(
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
