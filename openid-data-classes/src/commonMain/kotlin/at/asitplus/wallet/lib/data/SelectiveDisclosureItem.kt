package at.asitplus.wallet.lib.data

import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.hash.digest
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Selective Disclosure item in SD-JWT format
 */
@Serializable(with = SelectiveDisclosureItemSerializer::class)
data class SelectiveDisclosureItem(
    val salt: ByteArray,
    val claimName: String?,
    val claimValue: JsonElement,
) {

    /**
     * Creates a disclosure, as described in section 4 of
     * [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html#name-disclosures)
     */
    fun toDisclosure() = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(this)
        .encodeToByteArray().encodeToString(Base64UrlStrict)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SelectiveDisclosureItem

        if (!salt.contentEquals(other.salt)) return false
        if (claimName != other.claimName) return false
        if (claimValue != other.claimValue) return false

        return true
    }

    override fun hashCode(): Int {
        var result = salt.contentHashCode()
        result = 31 * result + claimName.hashCode()
        result = 31 * result + claimValue.hashCode()
        return result
    }

    override fun toString(): String = "SelectiveDisclosureItem(" +
            "salt=${salt.encodeToString(Base64())}, " +
            "claimName='$claimName', " +
            "claimValue=$claimValue" +
            ")"

    companion object {
        /**
         * Hashes a disclosure from [SelectiveDisclosureItem.toDisclosure] according to section 4.2.3 of
         * [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html#name-hashing-disclosures)
         **/
        fun String.hashDisclosure(digest: Digest = Digest.SHA256) =
            digest.digest(this.encodeToByteArray()).encodeToString(Base64UrlStrict)
    }

}
