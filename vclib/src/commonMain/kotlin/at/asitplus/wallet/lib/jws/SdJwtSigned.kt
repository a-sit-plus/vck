package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.github.aakira.napier.Napier

/**
 * Representation of a signed SD-JWT, i.e. consisting of an JWS (with header, payload and signature) and several
 * disclosures separated by a `~`
 */
data class SdJwtSigned(
    val jws: JwsSigned,
    val disclosures: List<SelectiveDisclosureItem>
) {
    fun serialize(): String {
        return (listOf(jws.serialize()) + disclosures.map { it.serialize() }).joinToString("~")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SdJwtSigned

        if (jws != other.jws) return false
        if (disclosures != other.disclosures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = jws.hashCode()
        result = 31 * result + disclosures.hashCode()
        return result
    }

    companion object {
        fun parse(input: String): SdJwtSigned? {
            val stringList = input.replace("[^A-Za-z0-9-_.~]".toRegex(), "").split("~")
            if (stringList.isEmpty()) return null.also { Napier.w("Could not parse SD-JWT: $input") }
            val jws = JwsSigned.parse(stringList.first())
                ?: return null.also { Napier.w("Could not parse JWS from SD-JWT: $input") }
            val disclosures = stringList.drop(1).mapNotNull { SelectiveDisclosureItem.deserialize(it) }
            if (disclosures.count() != stringList.count() - 1)
                return null.also { Napier.w("Could not parse disclosures: $input") }
            return SdJwtSigned(jws, disclosures)
        }
    }
}