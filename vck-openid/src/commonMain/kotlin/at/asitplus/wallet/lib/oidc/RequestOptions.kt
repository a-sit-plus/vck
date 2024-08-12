package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_PROFILE
import com.benasher44.uuid.uuid4
import io.ktor.http.*

data class RequestOptions(
    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode]
     */
    val responseMode: OpenIdConstants.ResponseMode? = null,
    /**
     * Required representation, see [ConstantIndex.CredentialRepresentation]
     */
    val representation: ConstantIndex.CredentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
    /**
     * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    val state: String? = uuid4().toString(),
    /**
     * Credential type to request, or `null` to make no restrictions
     */
    val credentialScheme: ConstantIndex.CredentialScheme? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions
     */
    val requestedAttributes: List<String>? = null,
    /**
     * Optional URL to include [metadata] by reference instead of by value (directly embedding in authn request)
     */
    val clientMetadataUrl: String? = null,
    /**
     * Set this value to include metadata with encryption parameters set. Beware if setting this value and also
     * [clientMetadataUrl], that the URL shall point to [getCreateMetadataWithEncryption].
     */
    val encryption: Boolean = false,
) {
    internal fun buildScope() = listOfNotNull(
        SCOPE_OPENID,
        SCOPE_PROFILE,
        credentialScheme?.sdJwtType,
        credentialScheme?.vcType,
        credentialScheme?.isoNamespace
    ).joinToString(" ")

    internal fun setRedirectUrl(): Boolean =
        if ((responseMode == OpenIdConstants.ResponseMode.DIRECT_POST) || (responseMode == OpenIdConstants.ResponseMode.DIRECT_POST_JWT)) false else true

    internal fun toInputDescriptor() = InputDescriptor(
        id = buildId(),
        schema = listOfNotNull(credentialScheme?.schemaUri?.let { SchemaReference(it) }),
        constraints = toConstraint(),
    )

    private fun ConstantIndex.CredentialScheme?.toConstraintField(attributeType: String) = ConstraintField(
        path = listOf(
            NormalizedJsonPath(
                NormalizedJsonPathSegment.NameSegment(this?.isoNamespace ?: "mdoc"),
                NormalizedJsonPathSegment.NameSegment(attributeType),
            ).toString()
        ), intentToRetain = false
    )

    private fun List<String>.createConstraints(
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme?,
    ): Collection<ConstraintField> = map {
        if (credentialRepresentation == ConstantIndex.CredentialRepresentation.ISO_MDOC) credentialScheme.toConstraintField(
            it
        )
        else ConstraintField(path = listOf("\$[${it.quote()}]"))
    }

    /**
     * doctype is not really an attribute that can be presented,
     * encoding it into the descriptor id as in the following non-normative example fow now:
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.3.1-4
     */
    private fun buildId() =
        if (credentialScheme?.isoDocType != null && representation == ConstantIndex.CredentialRepresentation.ISO_MDOC) credentialScheme.isoDocType!! else uuid4().toString()

    private fun toConstraint() = Constraint(fields = (toAttributeConstraints() + toTypeConstraint()).filterNotNull())

    private fun RequestOptions.toAttributeConstraints() =
        requestedAttributes?.createConstraints(representation, credentialScheme) ?: listOf()

    private fun toTypeConstraint() = credentialScheme?.let {
        when (representation) {
            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> it.toVcConstraint()
            ConstantIndex.CredentialRepresentation.SD_JWT -> it.toSdJwtConstraint()
            ConstantIndex.CredentialRepresentation.ISO_MDOC -> null
        }
    }

    companion object {
        private fun requestedAttributesFromConstraintFields(constraints: Collection<ConstraintField>): List<String> {
            val regex = "[a-zA-Z]+".toRegex()
            return constraints.map { constraint -> regex.find(constraint.path.last())?.value ?: "" }
        }

        fun fromInputDescriptor(inputDescriptor: InputDescriptor): List<RequestOptions> {
            val req = requestedAttributesFromConstraintFields(inputDescriptor.constraints?.fields ?: emptyList())
            val rep = inputDescriptor.format?.toSetOfRepresentation() ?: emptySet()
            return rep.map { RequestOptions(representation = it, requestedAttributes = req) }
        }
    }
}

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