package at.asitplus.wallet.lib.data.rfc8392.cwt

import kotlin.jvm.JvmInline

/**
 * specification: https://www.rfc-editor.org/rfc/rfc8392
 *
 * The human-readable name used to identify a claim.
 */
@JvmInline
value class CwtClaimName(val value: String) {
    override fun toString() = value
}