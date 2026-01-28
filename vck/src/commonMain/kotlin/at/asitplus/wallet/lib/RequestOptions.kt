package at.asitplus.wallet.lib

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.RequirementEnum
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import com.benasher44.uuid.uuid4
import kotlinx.serialization.json.JsonPrimitive
import kotlin.collections.plus

// TODO Should be NormalizedJsonPath
typealias RequestedAttributes = Set<String>

interface RequestOptions {
    val credentials: Set<RequestOptionsCredential>
    val state: String
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
    /** ID to be used in [DifInputDescriptor] or [QesInputDescriptor], or [DCQLCredentialQuery] */
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
            CredentialRepresentation.SD_JWT -> FormatHolder(sdJwt = containerSdJwt)
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
