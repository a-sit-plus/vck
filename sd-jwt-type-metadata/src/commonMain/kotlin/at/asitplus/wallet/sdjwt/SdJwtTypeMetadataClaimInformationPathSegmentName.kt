package at.asitplus.wallet.sdjwt

import kotlin.jvm.JvmInline

@JvmInline
value class SdJwtTypeMetadataClaimInformationPathSegmentName(
    val string: String
) : SdJwtTypeMetadataClaimInformationPathSegment {
    override fun toString() = "\"$string\""
}