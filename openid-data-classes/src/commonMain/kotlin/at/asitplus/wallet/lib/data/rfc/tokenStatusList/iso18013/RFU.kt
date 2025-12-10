package at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013

import kotlinx.serialization.Serializable

/**
 * Placeholder class used in cbor/ISO
 * Throws away anything that would be associated with this class
 */
@Serializable
class RFU {
    override fun equals(other: Any?): Boolean = other is RFU
    override fun hashCode(): Int = 0
}