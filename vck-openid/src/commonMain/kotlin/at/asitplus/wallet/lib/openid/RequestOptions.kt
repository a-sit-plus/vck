package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.*
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryInstance
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import com.benasher44.uuid.uuid4
import io.ktor.http.*

typealias RequestedAttributes = Set<String>

interface RequestOptions {
    /**
     * Requested credentials, should be at least one
     */
    val credentials: Set<RequestOptionsCredential>

    /**
     * Presentation mechanism to be used for requesting credentials
     */
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

    /**
     * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
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

    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")

    fun toDCQLQuery(): DCQLQuery?

    fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
    ): PresentationDefinition?

    fun toInputDescriptor(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
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
) : RequestOptions {
    override fun toDCQLQuery(): DCQLQuery? = if (credentials.isEmpty()) null else DCQLQuery(
        credentials = toDCQLCredentialQueryList(),
    )

    private fun toDCQLCredentialQueryList(): DCQLCredentialQueryList<DCQLCredentialQuery> = DCQLCredentialQueryList(
        credentials.map { credential ->
            val format = when (credential.representation) {
                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
                ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialFormatEnum.DC_SD_JWT
                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
            }
            val meta = when (credential.representation) {
                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> null
                ConstantIndex.CredentialRepresentation.SD_JWT -> DCQLSdJwtCredentialMetadataAndValidityConstraints(
                    vctValues = listOf(credential.credentialScheme.sdJwtType!!)
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                    doctypeValue = credential.credentialScheme.isoDocType!!
                )
            }
            val claims = credential.requestedAttributes?.let { attributes ->
                DCQLClaimsQueryList(
                    attributes.map { attribute ->
                        when (credential.representation) {
                            ConstantIndex.CredentialRepresentation.SD_JWT,
                            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> DCQLJsonClaimsQuery(
                                path = DCQLClaimsPathPointer(attribute)
                            )

                            ConstantIndex.CredentialRepresentation.ISO_MDOC -> DCQLIsoMdocClaimsQuery(
                                namespace = credential.credentialScheme.isoNamespace!!,
                                claimName = attribute,
                            )
                        }
                    }.toNonEmptyList()
                )
            }
            DCQLCredentialQueryInstance(
                id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                format = format,
                meta = meta,
                claims = claims,
            )
        }.toNonEmptyList()
    )

    override fun toPresentationDefinition(
        containerJwt: FormatContainerJwt,
        containerSdJwt: FormatContainerSdJwt,
    ): PresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = this.toInputDescriptor(containerJwt, containerSdJwt)
    )

    override fun toInputDescriptor(
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
    /**
     * Credential type to request, or `null` to make no restrictions
     */
    val credentialScheme: ConstantIndex.CredentialScheme,
    /**
     * Required representation, see [ConstantIndex.CredentialRepresentation]
     */
    val representation: ConstantIndex.CredentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions
     */
    val requestedAttributes: RequestedAttributes? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional),
     * or `null` to make no restrictions
     */
    val requestedOptionalAttributes: RequestedAttributes? = null,
) {
    fun buildId() =
        if (credentialScheme.isoDocType != null && representation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
            credentialScheme.isoDocType!! else uuid4().toString()

    fun toConstraint() =
        Constraint(fields = (requiredAttributes() + optionalAttributes() + toTypeConstraint()).filterNotNull())

    private fun requiredAttributes() =
        requestedAttributes?.createConstraints(representation, credentialScheme, false)?.toSet()
            ?: setOf()

    private fun optionalAttributes() =
        requestedOptionalAttributes?.createConstraints(representation, credentialScheme, true)
            ?: listOf()

    private fun toTypeConstraint() = when (representation) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> this.credentialScheme.toVcConstraint()
        ConstantIndex.CredentialRepresentation.SD_JWT -> this.credentialScheme.toSdJwtConstraint()
        ConstantIndex.CredentialRepresentation.ISO_MDOC -> null
    }

    fun toFormatHolder(containerJwt: FormatContainerJwt, containerSdJwt: FormatContainerSdJwt) =
        when (representation) {
            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> FormatHolder(jwtVp = containerJwt)
            ConstantIndex.CredentialRepresentation.SD_JWT -> FormatHolder(
                jwtSd = containerSdJwt,
                sdJwt = containerSdJwt
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> FormatHolder(msoMdoc = containerJwt)
        }

    private fun RequestedAttributes.createConstraints(
        representation: ConstantIndex.CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme?,
        optional: Boolean,
    ): Collection<ConstraintField> = map {
        if (representation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
            credentialScheme.toConstraintField(it, optional)
        else
            ConstraintField(path = listOf("\$[${it.quote()}]"), optional = optional)
    }

    private fun ConstantIndex.CredentialScheme?.toConstraintField(
        attributeType: String,
        optional: Boolean,
    ) = ConstraintField(
        path = listOf(
            NormalizedJsonPath(
                NormalizedJsonPathSegment.NameSegment(this?.isoNamespace ?: "mdoc"),
                NormalizedJsonPathSegment.NameSegment(attributeType),
            ).toString()
        ),
        intentToRetain = false,
        optional = optional,
    )

    private fun ConstantIndex.CredentialScheme.toVcConstraint() = if (supportsVcJwt)
        ConstraintField(
            path = listOf("$.type"),
            filter = ConstraintFilter(
                type = "string",
                pattern = vcType,
            )
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtConstraint() = if (supportsSdJwt)
        ConstraintField(
            path = listOf("$.vct"),
            filter = ConstraintFilter(
                type = "string",
                pattern = sdJwtType!!
            )
        ) else null
}
