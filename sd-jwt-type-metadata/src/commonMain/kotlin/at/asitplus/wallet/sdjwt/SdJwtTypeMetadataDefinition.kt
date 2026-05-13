package at.asitplus.wallet.sdjwt

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

/**
 * Metadata for an SD-JWT VC Type
 * According to
 * https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html#name-display-metadata
 */
@Serializable
@JsonIgnoreUnknownKeys
data class SdJwtTypeMetadataDefinition(
    @SerialName(SerialNames.VCT)
    val vct: SdJwtVcType,
    @SerialName(SerialNames.NAME)
    val name: String? = null,
    @SerialName(SerialNames.DESCRIPTION)
    val description: String? = null,
    @SerialName(SerialNames.EXTENDS)
    val extends: SdJwtVcType? = null,
    @SerialName(SerialNames.EXTENDS_INTEGRITY)
    val extendsIntegrity: W3cSubresourceIntegrityMetadata? = null,
    @SerialName(SerialNames.DISPLAY)
    val display: SdJwtTypeMetadataTypeDisplayInformationList? = null,
    @SerialName(SerialNames.CLAIMS)
    val claims: SdJwtTypeMetadataClaimInformationList? = null,
) {
    object SerialNames {
        const val VCT = "vct"
        const val NAME = "name"
        const val DESCRIPTION = "description"
        const val EXTENDS = "extends"
        const val EXTENDS_INTEGRITY = "extends#integrity"
        const val DISPLAY = "display"
        const val CLAIMS = "claims"
    }

    fun toSdJwtTypeMetadata(): SdJwtTypeMetadata {
        require(extends == null && extendsIntegrity == null) {
            "Expected metadata definition to not extend anything, but got `${this}`."
        }
        return SdJwtTypeMetadata(
            vct = vct,
            name = name,
            description = description,
            display = display,
            claims = claims,
        )
    }

    fun extend(base: SdJwtTypeMetadata): SdJwtTypeMetadata {
        require(extends == base.vct) {
            """Expected the extending type to specify the vct of the extended type in `extends`, but got `${extends}` instead of `${base.vct}` in `$this`"""
        }

        return SdJwtTypeMetadata(
            vct = vct,
            name = name ?: base.name,
            description = description ?: base.description,
            /**
             * When an SD-JWT VC type extends another type as described in Section 4.4, the display metadata remains
             * valid for the inheriting type unless that type defines its own display property, in which case the
             * original display metadata is ignored.
             */
            display = display ?: base.display,
            claims = claims?.let {
                val childClaims = it.associateBy {
                    it.path
                }
                val baseClaims = (base.claims ?: listOf()).associateBy {
                    it.path
                }
                (childClaims.keys + baseClaims.keys).associateWith {
                    val baseClaimInfo = baseClaims[it]
                    val childClaimInfo = childClaims[it] ?: return@associateWith baseClaimInfo
                    if (baseClaimInfo == null) {
                        return@associateWith childClaimInfo
                    }
                    childClaimInfo.extendFrom(baseClaimInfo)
                }.values.filterNotNull()
            }?.let(::SdJwtTypeMetadataClaimInformationList) ?: base.claims
        )
    }
}


