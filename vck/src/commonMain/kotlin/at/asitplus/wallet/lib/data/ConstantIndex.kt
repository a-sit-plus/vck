package at.asitplus.wallet.lib.data

import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegment
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentIndex
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentString
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.sdjwt.CredentialFormatEnum
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadata
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformation
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegment
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentIndex
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataClaimInformationPathSegmentName

object ConstantIndex {

    enum class CredentialRepresentation {
        PLAIN_JWT,
        SD_JWT,
        ISO_MDOC,
    }

    @Deprecated(
        "Replace with direct import",
        ReplaceWith("CredentialScheme", "at.asitplus.wallet.lib.data.CredentialScheme")
    )
    interface CredentialScheme : at.asitplus.wallet.lib.data.CredentialScheme

    object AtomicAttribute2023 : SdJwtCredentialScheme, IsoMdocCredentialScheme, VcJwtCredentialScheme {
        const val CLAIM_GIVEN_NAME = "given_name"
        const val CLAIM_FAMILY_NAME = "family_name"
        const val CLAIM_DATE_OF_BIRTH = "date_of_birth"
        const val CLAIM_PORTRAIT = "portrait"
        @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
        override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/AtomicAttribute2023.json"
        override val vcType: String = "AtomicAttribute2023"
        override val sdJwtType: String = "AtomicAttribute2023"
        override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2023"
        override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2023.iso"
        override val claimDescriptions: Set<ClaimDescription>
            get() = setOf(
                ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_GIVEN_NAME)),
                ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_FAMILY_NAME)),
                ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_DATE_OF_BIRTH)),
                ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_PORTRAIT)),
            )
        override val supportedRepresentations: Collection<CredentialRepresentation>
            get() = listOf(ISO_MDOC, PLAIN_JWT, SD_JWT)
    }

    @Suppress("DEPRECATION")
    @Deprecated(
        "Use type check for SdJwtCredentialScheme",
        ReplaceWith("this is SdJwtCredentialScheme")
    )
    val at.asitplus.wallet.lib.data.CredentialScheme.supportsSdJwt
        get() = (this is SdJwtCredentialScheme) ||
                (supportedRepresentations.contains(SD_JWT) && sdJwtType != null)

    @Suppress("DEPRECATION")
    @Deprecated(
        "Use type check for VcJwtCredentialScheme",
        ReplaceWith("this is VcJwtCredentialScheme")
    )
    val at.asitplus.wallet.lib.data.CredentialScheme.supportsVcJwt
        get() = (this is VcJwtCredentialScheme) ||
                (supportedRepresentations.contains(PLAIN_JWT) && vcType != null)

    @Suppress("DEPRECATION")
    @Deprecated(
        "Use type check for IsoMdocCredentialScheme",
        ReplaceWith("this is IsoMdocCredentialScheme")
    )
    val at.asitplus.wallet.lib.data.CredentialScheme.supportsIso
        get() = (this is IsoMdocCredentialScheme) ||
                (supportedRepresentations.contains(ISO_MDOC) && isoNamespace != null && isoDocType != null)

}

typealias CredentialRepresentation = ConstantIndex.CredentialRepresentation

/**
 * Holds all information needed to define one type of "credential", i.e. a collection of claims about a subject.
 */
interface CredentialScheme {
    @Deprecated("Use other identifiers instead, e.g. `vcType` or `sdJwtType` or `isoDocType`")
    val schemaUri: String
        get() = ""

    /**
     * The `type` of the credential when using [ConstantIndex.CredentialRepresentation.PLAIN_JWT].
     * Will not be used for other representations.
     * Previously this has been used as the subtype of `CredentialSubject`, but this class has been removed.
     *
     * From W3C VC Data Model:
     * The value of the `type` property MUST be one or more terms and absolute URL strings.
     * If more than one value is provided, the order does not matter.
     */
    val vcType: String?
        get() = null

    /**
     * Type used for `vct` when using [ConstantIndex.CredentialRepresentation.SD_JWT].
     *
     * From IETF Draft SD-JWT VC:
     * Its value MUST be a case-sensitive string serving as an identifier for the type of the SD-JWT VC.
     * The `vct` value MUST be a Collision-Resistant Name as defined in Section 2 of
     * [RFC7515](https://www.rfc-editor.org/info/rfc7515).
     */
    val sdJwtType: String?
        get() = null

    /**
     * Namespace to use for attributes of this credential type, when using [ConstantIndex.CredentialRepresentation.ISO_MDOC].
     *
     * From ISO/IEC 18013-5:
     * There is no requirement for the `NameSpace` format. An approach to avoid collisions is to use the
     * following general format: `[Reverse Domain].[Domain Specific Extension]`.
     */
    val isoNamespace: String?
        get() = null

    /**
     * ISO DocType to use for attributes of this credential type, when using [ConstantIndex.CredentialRepresentation.ISO_MDOC].
     *
     * From ISO/IEC 18013-5:
     * There is no requirement for the `DocType` format. An approach to avoid collisions is to use the
     * following general format: `[Reverse Domain].[Domain Specific Extension]`.
     */
    val isoDocType: String?
        get() = null

    /**
     * List of claims that may be issued separately when requested in format [ConstantIndex.CredentialRepresentation.SD_JWT]
     * or [ConstantIndex.CredentialRepresentation.ISO_MDOC].
     */
    @Deprecated("Use claimDescriptions instead")
    val claimNames: Collection<String>
        get() = listOf()

    /**
     * List of claims that may be issued separately when requested in format [ConstantIndex.CredentialRepresentation.SD_JWT]
     * or [ConstantIndex.CredentialRepresentation.ISO_MDOC].
     */
    val claimDescriptions: Set<ClaimDescription>
        get() = setOf()

    /**
     * Supported representations for this credential. Note that this is usually only one representation,
     * and should be replaced with the typed implementations of the interface [CredentialScheme].
     */
    val supportedRepresentations: Collection<CredentialRepresentation>
        get() = listOf(
            PLAIN_JWT,
            SD_JWT,
            ISO_MDOC
        )
}

interface SdJwtCredentialScheme : CredentialScheme {

    /**
     * From IETF Draft SD-JWT VC:
     * Its value MUST be a case-sensitive string serving as an identifier for the type of the SD-JWT VC.
     * The `vct` value MUST be a Collision-Resistant Name as defined in Section 2 of
     * [RFC7515](https://www.rfc-editor.org/info/rfc7515).
     */
    override val sdJwtType: String

    @Suppress("DEPRECATION")
    override val claimDescriptions: Set<ClaimDescription>
        get() = claimNames.map {
            ClaimDescription(path = OpenId4VciClaimsPathPointer(it.split(".")))
        }.toSet()

    override val supportedRepresentations: Collection<CredentialRepresentation>
        get() = listOf(SD_JWT)
}

interface IsoMdocCredentialScheme : CredentialScheme {

    /**
     * From ISO/IEC 18013-5:
     * There is no requirement for the `DocType` format. An approach to avoid collisions is to use the
     * following general format: `[Reverse Domain].[Domain Specific Extension]`.
     */
    override val isoDocType: String

    /**
     * From ISO/IEC 18013-5:
     * There is no requirement for the `NameSpace` format. An approach to avoid collisions is to use the
     * following general format: `[Reverse Domain].[Domain Specific Extension]`.
     */
    override val isoNamespace: String

    @Suppress("DEPRECATION")
    override val claimDescriptions: Set<ClaimDescription>
        get() = claimNames.map {
            ClaimDescription(
                path = OpenId4VciClaimsPathPointer(listOf(isoNamespace) + it.replace("$isoNamespace.", "").split("."))
            )
        }.toSet()

    override val supportedRepresentations: Collection<CredentialRepresentation>
        get() = listOf(ISO_MDOC)
}

interface VcJwtCredentialScheme : CredentialScheme {

    /**
     * From W3C VC Data Model:
     * The value of the `type` property MUST be one or more terms and absolute URL strings.
     * If more than one value is provided, the order does not matter.
     */
    override val vcType: String

    @Suppress("DEPRECATION")
    override val claimDescriptions: Set<ClaimDescription>
        get() = claimNames.map {
            ClaimDescription(path = OpenId4VciClaimsPathPointer(it.split(".")))
        }.toSet()

    override val supportedRepresentations: Collection<CredentialRepresentation>
        get() = listOf(PLAIN_JWT)
}

