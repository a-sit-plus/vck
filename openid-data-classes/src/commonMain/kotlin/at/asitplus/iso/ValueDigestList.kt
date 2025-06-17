package at.asitplus.iso

import kotlinx.serialization.Serializable

/**
 * Convenience class with a custom serializer ([ValueDigestListSerializer]) to prevent
 * usage of the type `Map<String, Map<UInt, ByteArray>>` in [at.asitplus.wallet.lib.iso.MobileSecurityObject.valueDigests].
 */
@Serializable(with = ValueDigestListSerializer::class)
data class ValueDigestList(
    val entries: List<ValueDigest>
)