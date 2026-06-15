package at.asitplus.wallet.sdjwt

import kotlin.jvm.JvmInline

@JvmInline
value class SdJwtTypeMetadataClaimInformationPathSegmentIndex(
    val ulong: ULong
) : SdJwtTypeMetadataClaimInformationPathSegment {
    init {
        require(ulong <= Long.MAX_VALUE.toULong()) {
            "Expected value to be at most ${Long.MAX_VALUE}, but was $ulong"
        }
    }

    constructor(int: Int): this(int.also {
        require(it >= 0) {
            "Expected index segment to be non-negative, but was $it."
        }
    }.toULong())

    override fun toString() = ulong.toString()
}