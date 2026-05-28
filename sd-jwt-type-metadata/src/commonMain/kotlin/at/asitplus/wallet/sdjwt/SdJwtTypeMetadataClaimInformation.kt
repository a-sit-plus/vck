package at.asitplus.wallet.sdjwt

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  4.6. Claim Metadata
 *
 * The claims property is an array of objects that provides per-claim metadata. Each object identifies which claim or set of claims in the credential is being described (path), and can specify how that claim is presented to end users (display), whether it is required to be included by the Issuer (mandatory), whether it is selectively disclosable (sd), and, for SVG rendering, which placeholder refers to it (svg_id).
 *
 * The array MAY contain an object for each claim that is supported by the type. Each object contains the following properties:
 *
 *     path: An array indicating the claim or claims that are being addressed, as described below. This property is REQUIRED.
 *     display: An array containing display information for the claim or claims that are being addressed, as described in Section 4.6.2. This property is OPTIONAL.
 *     mandatory: A boolean indicating that the claim must be present in the issued credential. This property is OPTIONAL.
 *      If omitted, the default value is false. See Section 4.6.3 for details.
 *     sd: A string indicating whether the claim is selectively disclosable, as described in Section 4.6.4. This property is OPTIONAL.
 *     svg_id: A string defining the ID of the claim for reference in the SVG template, as described in Section 4.5.1.2.2.
 *      The ID MUST be unique within the type metadata.
 *      It MUST consist of only alphanumeric characters and underscores and MUST NOT start with a digit. This property is OPTIONAL.
 */
@Serializable
data class SdJwtTypeMetadataClaimInformation(
    @SerialName(SerialNames.PATH)
    val path: SdJwtTypeMetadataClaimInformationPath,
    @SerialName(SerialNames.DISPLAY)
    val display: SdJwtTypeMetadataClaimInformationDisplayMetadataList? = null,
    @SerialName(SerialNames.MANDATORY)
    val isMandatory: Boolean? = null,
    @SerialName(SerialNames.SD)
    val selectiveDisclosureConstraints: SelectiveDisclosureConstraints? = null,
    @SerialName(SerialNames.SVG_ID)
    val svgId: SvgContentPlaceholder? = null,
) {
    object SerialNames {
        const val PATH = "path"
        const val DISPLAY = "display"
        const val MANDATORY = "mandatory"
        const val SD = "sd"
        const val SVG_ID = "svg_id"
    }

    /**
     * Considering this to be the claim information of the parent type, these are the semantics for inheritance.
     */
    fun extendFrom(base: SdJwtTypeMetadataClaimInformation): SdJwtTypeMetadataClaimInformation {
        val child = this
        require(base.path == child.path) {
            "Expected paths to be the same, but got `${child.path}` instead of `${base.path}`"
        }
        return SdJwtTypeMetadataClaimInformation(
            path = base.path,
            display = child.display ?: base.display,
            isMandatory = if (child.isMandatory != null) child.extendFromMandatory(base.isMandatory) else base.isMandatory,
            selectiveDisclosureConstraints = when {
                child.selectiveDisclosureConstraints != null ->
                    child.selectiveDisclosureConstraints.extendFrom(base.selectiveDisclosureConstraints ?: SelectiveDisclosureConstraints.ALLOWED)
                else -> base.selectiveDisclosureConstraints
            },
            svgId = child.svgId ?: base.svgId,
        )
    }

    private fun extendFromMandatory(isBaseMandatory: Boolean?): Boolean {
        return when (isBaseMandatory) {
            null, false -> this.isMandatory!!
            true -> {
                require(this.isMandatory!!) {
                    "An extending type can set the mandatory property of a claim that is optional in the extended type to true, but it MUST NOT change a claim that is mandatory in the extended type to false."
                }
                true
            }
        }
    }
}
