package at.asitplus.wallet.lib.openid

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.CREDENTIAL_TYPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.wallet.lib.oidvci.AuthorizationDetails
import at.asitplus.wallet.lib.oidvci.CredentialFormatEnum
import at.asitplus.wallet.lib.oidvci.CredentialRequestParameters
import at.asitplus.wallet.lib.oidvci.CredentialRequestProof
import at.asitplus.wallet.lib.oidvci.SupportedCredentialFormatDefinition
import at.asitplus.wallet.lib.oidvci.toRequestedClaimsIso
import at.asitplus.wallet.lib.oidvci.toRequestedClaimsSdJwt
import com.benasher44.uuid.uuid4
import io.ktor.http.*
import kotlinx.datetime.Clock


data class RequestOptions(
    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode]
     */
    val responseMode: OpenIdConstants.ResponseMode? = null,
    /**
     * Required representation, see [ConstantIndex.CredentialRepresentation]
     */
    val representation: CredentialRepresentation = PLAIN_JWT,
    /**
     * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    val state: String = uuid4().toString(),
    /**
     * Credential type to request, or `null` to make no restrictions
     */
    val credentialScheme: ConstantIndex.CredentialScheme? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions
     */
    val requestedAttributes: Collection<String>? = null,
    /**
     * Optional URL to include [metadata] by reference instead of by value (directly embedding in authn request)
     */
    val clientMetadataUrl: String? = null,
    /**
     * Set this value to include metadata with encryption parameters set. Beware if setting this value and also
     * [clientMetadataUrl], that the URL shall point to [getCreateMetadataWithEncryption].
     */
    val encryption: Boolean = false,
    /**
     * Modify clock for testing specific scenarios
     */
    val clock: Clock = Clock.System,
) {

    internal fun toInputDescriptor() = InputDescriptor(
        id = buildId(),
        schema = listOfNotNull(credentialScheme?.schemaUri?.let { SchemaReference(it) }),
        constraints = toConstraint(),
    )

    internal fun toCredentialRequestParameters(proof: CredentialRequestProof) = credentialScheme?.let {
        representation.toCredentialRequestParameters(it, requestedAttributes?.toSet(), proof)
    }

    internal fun toAuthnDetails() = credentialScheme?.let {
        representation.toAuthorizationDetails(it, requestedAttributes?.toSet())
    }

    internal fun buildScope() = listOfNotNull(
        SCOPE_OPENID,
        SCOPE_PROFILE,
        credentialScheme?.sdJwtType,
        credentialScheme?.vcType,
        credentialScheme?.isoNamespace
    ).joinToString(" ")

    internal fun includeRedirectUrl(): Boolean =
        !((responseMode == OpenIdConstants.ResponseMode.DIRECT_POST) || (responseMode == OpenIdConstants.ResponseMode.DIRECT_POST_JWT))

    /**
     * doctype is not really an attribute that can be presented,
     * encoding it into the descriptor id as in the following non-normative example fow now:
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.3.1-4
     */
    private fun buildId() =
        if (credentialScheme?.isoDocType != null && representation == ISO_MDOC) credentialScheme.isoDocType!! else uuid4().toString()

    private fun toConstraint() = Constraint(fields = (toAttributeConstraints() + toTypeConstraint()).filterNotNull())

    private fun toAttributeConstraints() =
        requestedAttributes?.createConstraints(representation, credentialScheme) ?: listOf()

    private fun toTypeConstraint() = credentialScheme?.let {
        when (representation) {
            PLAIN_JWT -> it.toVcConstraint()
            SD_JWT -> it.toSdJwtConstraint()
            ISO_MDOC -> null
        }
    }
}

/**
 * Miscellaneous helper functions regarding [ConstraintField]
 */
private fun Collection<ConstraintField>.toRequestedAttributes(): List<String> {
    val regex = "[a-zA-Z0-9_-]+".toRegex()
    val rawAttributes = this.map { constraint -> constraint.path.last().split("[").last() }
    return rawAttributes.map { regex.find(it)?.value ?: "" }
}

private fun Collection<String>.createConstraints(
    credentialRepresentation: CredentialRepresentation,
    credentialScheme: ConstantIndex.CredentialScheme?,
): Collection<ConstraintField> = map {
    if (credentialRepresentation == ISO_MDOC) credentialScheme.toConstraintField(
        it
    )
    else ConstraintField(path = listOf("\$[${it.quote()}]"))
}

private fun ConstantIndex.CredentialScheme?.toConstraintField(attributeType: String) = ConstraintField(
    path = listOf(
        NormalizedJsonPath(
            NormalizedJsonPathSegment.NameSegment(this?.isoNamespace ?: "mdoc"),
            NormalizedJsonPathSegment.NameSegment(attributeType),
        ).toString()
    ), intentToRetain = false
)

private fun ConstantIndex.CredentialScheme.toVcConstraint() = if (supportsVcJwt) ConstraintField(
    path = listOf("$.type"), filter = ConstraintFilter(
        type = "string",
        pattern = vcType,
    )
) else null

private fun ConstantIndex.CredentialScheme.toSdJwtConstraint() = if (supportsSdJwt) ConstraintField(
    path = listOf("$.vct"), filter = ConstraintFilter(
        type = "string", pattern = sdJwtType!!
    )
) else null

/**
 * Miscellaneous helper functions regarding [AuthorizationDetails]
 */
private fun CredentialRepresentation.toAuthorizationDetails(
    scheme: ConstantIndex.CredentialScheme,
    requestedAttributes: Set<String>?,
) = when (this) {
    PLAIN_JWT -> scheme.toJwtAuthn(toFormat())
    SD_JWT -> scheme.toSdJwtAuthn(toFormat(), requestedAttributes)
    ISO_MDOC -> scheme.toIsoAuthn(toFormat(), requestedAttributes)
}

private fun ConstantIndex.CredentialScheme.toJwtAuthn(
    format: CredentialFormatEnum,
) = if (supportsVcJwt)
    AuthorizationDetails(
        type = CREDENTIAL_TYPE_OPENID,
        format = format,
        credentialDefinition = SupportedCredentialFormatDefinition(
            types = listOf(VERIFIABLE_CREDENTIAL, vcType!!),
        ),
    ) else null

private fun ConstantIndex.CredentialScheme.toSdJwtAuthn(
    format: CredentialFormatEnum,
    requestedAttributes: Set<String>?,
) = if (supportsSdJwt)
    AuthorizationDetails(
        type = CREDENTIAL_TYPE_OPENID,
        format = format,
        sdJwtVcType = sdJwtType!!,
        claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtType!!),
    ) else null

private fun ConstantIndex.CredentialScheme.toIsoAuthn(
    format: CredentialFormatEnum,
    requestedAttributes: Set<String>?,
) = if (supportsIso)
    AuthorizationDetails(
        type = CREDENTIAL_TYPE_OPENID,
        format = format,
        docType = isoDocType,
        claims = requestedAttributes?.toRequestedClaimsIso(isoNamespace!!)
    ) else null


private fun CredentialRepresentation.toCredentialRequestParameters(
    credentialScheme: ConstantIndex.CredentialScheme,
    requestedAttributes: Set<String>?,
    proof: CredentialRequestProof,
) = when {
    this == PLAIN_JWT && credentialScheme.supportsVcJwt -> CredentialRequestParameters(
        format = toFormat(),
        credentialDefinition = SupportedCredentialFormatDefinition(
            types = listOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType!!,
        ),
        proof = proof
    )

    this == SD_JWT && credentialScheme.supportsSdJwt -> CredentialRequestParameters(
        format = toFormat(),
        sdJwtVcType = credentialScheme.sdJwtType!!,
        claims = requestedAttributes?.toRequestedClaimsSdJwt(credentialScheme.sdJwtType!!),
        proof = proof
    )

    this == ISO_MDOC && credentialScheme.supportsIso -> CredentialRequestParameters(
        format = toFormat(),
        docType = credentialScheme.isoDocType,
        claims = requestedAttributes?.toRequestedClaimsIso(credentialScheme.isoNamespace!!),
        proof = proof
    )

    else -> throw IllegalArgumentException("format $this not applicable to $credentialScheme")
}

private fun CredentialRepresentation.toFormat() = when (this) {
    PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    SD_JWT -> CredentialFormatEnum.VC_SD_JWT
    ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}

/**
 * Inverse operation of [RequestOptions.toInputDescriptor]
 */

fun InputDescriptor.toRequestOptions(): RequestOptions? {
    val representationConstraints = mapOf(
        "type" to PLAIN_JWT, "vct" to SD_JWT
    )

    val credentialScheme = AttributeIndex.resolveSchemaUri(this.schema.first().uri)
    val requestedAttributes =
        (this.constraints?.fields?.toRequestedAttributes() ?: emptyList()).toMutableSet()

    val requestedScheme = representationConstraints.filterKeys { it in requestedAttributes }.values.toSet().apply {
        if (this.size > 1) throw Exception("Invalid requirement in InputDescriptor: Cannot be two schemes at the same time")
    }.firstOrNull() ?: ISO_MDOC // this assumes that ISO-MDOC is the only scheme which does not add a specific constraint

    requestedAttributes.removeAll(representationConstraints.keys)

    val isViableTypeConstraint = this.format?.toSetOfRepresentation()?.contains(requestedScheme)
        ?: true //assume that if not specified everything is supported

    return if (isViableTypeConstraint) {
        RequestOptions(
            credentialScheme = credentialScheme,
            representation = requestedScheme,
            requestedAttributes = requestedAttributes.toList()
        )
    } else null
}