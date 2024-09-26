package at.asitplus.wallet.lib.iso

import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Convenience class with a custom serializer ([ValueDigestListSerializer]) to prevent
 * usage of the type `Map<String, Map<UInt, ByteArray>>` in [MobileSecurityObject.valueDigests].
 */
data class ValueDigest(
    val key: UInt,
    val value: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ValueDigest

        if (key != other.key) return false
        return value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "ValueDigest(key=$key, value=${value.encodeToString(Base16(strict = true))})"
    }

    companion object {
        /**
         * Input for digest calculation is this structure:
         * `IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)`
         *
         * See ISO/IEC 18013-5:2021, 9.1.2.5 Message digest function
         */
        fun fromIssuerSigned(namespace: String, value: IssuerSignedItem) = ValueDigest(
            value.digestId,
            value.serialize(namespace).wrapInCborTag(24).sha256()
        )
    }
}