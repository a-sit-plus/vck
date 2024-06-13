package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/**
 * Representation of a signed SD-JWT (payload is [VerifiableCredentialSdJwt]),
 * i.e. consisting of an JWS (with header, payload and signature) and several
 * disclosures ([SelectiveDisclosureItem]) separated by a `~`, possibly ending with a JWS with payload [KeyBindingJws]
 */
data class SdJwtSigned(
    val jws: JwsSigned,
    val disclosures: Map<String, SelectiveDisclosureItem>,
    val keyBindingJws: JwsSigned? = null,
    val rawDisclosures: List<String>,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SdJwtSigned

        if (jws != other.jws) return false
        if (disclosures != other.disclosures) return false
        if (keyBindingJws != other.keyBindingJws) return false
        if (rawDisclosures != other.rawDisclosures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = jws.hashCode()
        result = 31 * result + disclosures.hashCode()
        result = 31 * result + (keyBindingJws?.hashCode() ?: 0)
        result = 31 * result + rawDisclosures.hashCode()
        return result
    }

    companion object {
        fun parse(input: String): SdJwtSigned? {
            if (!input.contains("~")) return null.also { Napier.w("Could not parse SD-JWT: $input") }
            val stringList = input.replace("[^A-Za-z0-9-_.~]".toRegex(), "").split("~")
            if (stringList.isEmpty()) return null.also { Napier.w("Could not parse SD-JWT: $input") }
            val jws = JwsSigned.parse(stringList.first()).getOrNull()
                ?: return null.also { Napier.w("Could not parse JWS from SD-JWT: $input") }
            val stringListWithoutJws = stringList.drop(1)
            val rawDisclosures = stringListWithoutJws
                .filterNot { it.contains(".") }
            val disclosures = stringListWithoutJws.take(rawDisclosures.count())
                .associateWith {
                    val decoded = it.decodeToByteArray(Base64UrlStrict).decodeToString()
                    SelectiveDisclosureItem.deserialize(decoded).getOrElse { ex ->
                        Napier.w("Could not parse SD Item: $it", ex)
                        return null
                    }
                }
            val keyBindingString = stringList.drop(1 + rawDisclosures.size).firstOrNull()
            val keyBindingJws = keyBindingString?.let { JwsSigned.parse(it).getOrNull() }
            return SdJwtSigned(jws, disclosures, keyBindingJws, rawDisclosures)
        }
    }

}