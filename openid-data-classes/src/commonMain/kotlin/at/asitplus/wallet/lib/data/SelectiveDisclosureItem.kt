package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.hash.digest
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * Selective Disclosure item in SD-JWT format
 */
@Serializable(with = SelectiveDisclosureItemSerializer::class)
data class SelectiveDisclosureItem(
    /**
     * The salt exactly as in the disclosure. It "MUST be a string" of any form (RFC 9901, 4.2.1), base64url-encoded
     * random data is only what an Issuer "can" use.
     */
    val salt: String,
    val claimName: String?,
    val claimValue: JsonElement,
) {

    /**
     * Base64url-encodes [salt], as an Issuer can do for "128 bits of cryptographically secure random data" (RFC 9901,
     * 4.2.1).
     */
    constructor(salt: ByteArray, claimName: String?, claimValue: JsonElement) :
            this(salt.encodeToString(Base64UrlStrict), claimName, claimValue)

    /**
     * Creates a disclosure, as described in section 4 of
     * [RFC 9901](https://datatracker.ietf.org/doc/html/rfc9901#name-disclosures)
     */
    fun toDisclosure() = joseCompliantSerializer.encodeToString<SelectiveDisclosureItem>(this)
        .encodeToByteArray().encodeToString(Base64UrlStrict)

    companion object {
        /**
         * Hashes a disclosure from [SelectiveDisclosureItem.toDisclosure] according to section 4.2.3 of
         * [RFC 9901](https://datatracker.ietf.org/doc/html/rfc9901#name-hashing-disclosures)
         **/
        fun String.hashDisclosure(digest: Digest = Digest.SHA256) =
            digest.digest(this.encodeToByteArray()).encodeToString(Base64UrlStrict)
    }

}
