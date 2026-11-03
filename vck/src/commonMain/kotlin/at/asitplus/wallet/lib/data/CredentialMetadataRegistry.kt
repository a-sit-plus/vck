package at.asitplus.wallet.lib.data

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.DisplayProperties
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
import kotlin.jvm.JvmOverloads

interface CredentialMetadataRegistry {
    suspend fun findEntry(
        identifier: String,
        representation: CredentialRepresentation,
    ): ResolvedCredentialMetadata?

    /**
     * Entries that can be resolved eagerly without network access, used to pre-seed the synchronous lookups in
     * [AttributeIndex]. Defaults to none; registries that must fetch on demand keep the default.
     */
    fun preloadEntries(): Collection<ResolvedCredentialMetadata> = emptyList()
}

data class ResolvedCredentialMetadata @JvmOverloads constructor(
    val metadata: SdJwtTypeMetadata,
    val loadedFrom: String,
    val aliases: Set<String> = emptySet(),
)

fun ResolvedCredentialMetadata.toCredentialScheme() = metadata.toCredentialScheme()

private fun SdJwtTypeMetadata.extractRepresentation() = when (vckExtensions?.format) {
    CredentialFormatEnum.JWT_VC -> PLAIN_JWT
    CredentialFormatEnum.DC_SD_JWT -> SD_JWT
    CredentialFormatEnum.MSO_MDOC -> ISO_MDOC
    else -> null
} ?: SD_JWT

/**
 * Derives a scheme from type metadata. ISO mdoc claim paths must include their namespace; they are preserved even
 * when [SdJwtTypeMetadataVckExtensions.isoNamespace][at.asitplus.wallet.sdjwt.SdJwtTypeMetadataVckExtensions.isoNamespace]
 * is absent or names a different namespace.
 */
fun SdJwtTypeMetadata.toCredentialScheme() = when (extractRepresentation()) {
    PLAIN_JWT -> ExtractedVcJwtCredentialScheme(
        vcType = vckExtensions?.vcType ?: vct.string,
        claimDescriptions = claims?.map { it.toClaimDescription() }?.toSet() ?: setOf()
    )

    SD_JWT -> ExtractedSdJwtCredentialScheme(
        sdJwtType = vct.string,
        claimDescriptions = claims?.map { it.toClaimDescription() }?.toSet() ?: setOf()
    )

    ISO_MDOC -> ExtractedIsoMdocCredentialScheme(
        isoDocType = vckExtensions?.isoDocType ?: vct.string,
        isoNamespace = vckExtensions?.isoNamespace ?: vct.string,
        claimDescriptions = claims?.map { it.toClaimDescription() }?.toSet() ?: setOf(),
        isoClaimPathsAreQualified = true,
    )
}

private fun SdJwtTypeMetadataClaimInformation.toClaimDescription(): ClaimDescription = ClaimDescription(
    path = OpenId4VciClaimsPathPointer(path.map {
        it.toSegment()
    }.toNonEmptyList()),
    mandatory = isMandatory,
    display = display?.map {
        DisplayProperties(
            locale = it.locale.string,
            name = it.label,
            description = it.description,
        )
    }?.toSet()
)

private fun SdJwtTypeMetadataClaimInformationPathSegment?.toSegment(): OpenId4VciClaimsPathPointerSegment? =
    when (this) {
        is SdJwtTypeMetadataClaimInformationPathSegmentIndex ->
            OpenId4VciClaimsPathPointerSegmentIndex(this.ulong.safeToUint())

        is SdJwtTypeMetadataClaimInformationPathSegmentName ->
            OpenId4VciClaimsPathPointerSegmentString(this.string)

        null -> null
    }

private fun ULong.safeToUint(): UInt = also {
    if (it > UInt.MAX_VALUE) {
        throw UnsupportedOperationException("This implementation only supports claims path pointer indices up to ${UInt.MAX_VALUE}, but got $it")
    }
}.toUInt()

data class ExtractedVcJwtCredentialScheme(
    override val vcType: String,
    override val claimDescriptions: Set<ClaimDescription>
) : VcJwtCredentialScheme

data class ExtractedSdJwtCredentialScheme(
    override val sdJwtType: String,
    override val claimDescriptions: Set<ClaimDescription>
) : SdJwtCredentialScheme

data class ExtractedIsoMdocCredentialScheme @JvmOverloads constructor(
    override val isoDocType: String,
    override val isoNamespace: String,
    override val claimDescriptions: Set<ClaimDescription>,
    override val isoClaimPathsAreQualified: Boolean = false,
) : IsoMdocCredentialScheme
