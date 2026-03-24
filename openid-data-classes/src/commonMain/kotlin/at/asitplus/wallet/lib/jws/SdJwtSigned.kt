package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.data.KeyBindingJws

/**
 * Representation of a signed SD-JWT,
 * as issued by an issuer or presented by a holder, i.e.
 * consisting of an JWS (with header, payload is [at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt] and signature)
 * and several disclosures ([at.asitplus.wallet.lib.data.SelectiveDisclosureItem]) separated by a `~`,
 * possibly ending with a [keyBindingJws], that is a JWS with payload [at.asitplus.wallet.lib.data.KeyBindingJws].
 */
data class SdJwtSigned(
    /**
     * Holds signed JWS in compact representation. To access the payload use
     * [at.asitplus.signum.indispensable.josef.JWS.getPayload]
     */
    val jws: JwsCompact,
    val rawDisclosures: List<String>,
    val keyBindingJws: JwsCompactTyped<KeyBindingJws>? = null,
    val hashInput: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SdJwtSigned

        if (jws != other.jws) return false
        if (rawDisclosures != other.rawDisclosures) return false
        if (keyBindingJws != other.keyBindingJws) return false
        if (hashInput != other.hashInput) return false

        return true
    }

    override fun hashCode(): Int {
        var result = jws.hashCode()
        result = 31 * result + rawDisclosures.hashCode()
        result = 31 * result + (keyBindingJws?.hashCode() ?: 0)
        result = 31 * result + hashInput.hashCode()
        return result
    }

    /**
     * Compact serialization: JWT in JWS compact serialization (Base64-URL with dots),
     * disclosures and key binding appended, separated by a tilde.
     */
    fun serialize() = keyBindingJws?.let {
        serializePresentation(jws, rawDisclosures.toSet(), it)
    } ?: (listOf(jws.toString()) + rawDisclosures).joinToString("~", postfix = "~")

    override fun toString(): String {
        return "SdJwtSigned(jws=$jws, " +
                "rawDisclosures=$rawDisclosures, " +
                "keyBindingJws=$keyBindingJws, " +
                "hashInput='$hashInput')"
    }

    companion object {
        fun issued(
            jws: JwsCompact,
            disclosures: List<String>,
        ) = SdJwtSigned(
            jws = jws,
            rawDisclosures = disclosures,
            keyBindingJws = null,
            hashInput = (listOf(jws.toString()) + disclosures).joinToString("~", postfix = "~")
        )

        fun presented(
            jws: JwsCompact,
            disclosures: Set<String>,
            keyBinding: JwsCompactTyped<KeyBindingJws>,
        ) = SdJwtSigned(
            jws = jws,
            rawDisclosures = disclosures.toList(),
            keyBindingJws = keyBinding,
            hashInput = (listOf(jws.toString()) + disclosures).joinToString("~", postfix = "~")
        )

        fun parseCatching(input: String): KmmResult<SdJwtSigned> = catching {
            require(input.contains("~")) { "Could not parse SD-JWT: $input" }
            val stringList = input.replace("[^A-Za-z0-9-_.~]".toRegex(), "").split("~")
            require(stringList.isNotEmpty()) { "Could not parse SD-JWT: $input" }
            val jws = JwsCompact(stringList.first())
            val stringListWithoutJws = stringList.drop(1)
            val rawDisclosures = stringListWithoutJws
                .filterNot { it.contains(".") }
                .filterNot { it.isEmpty() }
            val keyBindingString = stringList.drop(1 + rawDisclosures.size).firstOrNull()
            val keyBindingJws = keyBindingString?.takeIf { it.isNotEmpty() }?.let {
                JwsCompactTyped<KeyBindingJws>(it)
            }
            val hashInput = input.substringBeforeLast("~") + "~"
            SdJwtSigned(jws, rawDisclosures, keyBindingJws, hashInput)
        }

        /**
         * Compact serialization: JWT in JWS compact serialization (Base64-URL with dots),
         * disclosures and key binding appended, separated by a tilde.
         */
        fun serializePresentation(
            jwsFromIssuer: JwsCompact,
            filteredDisclosures: Set<String>,
            keyBinding: JwsCompactTyped<KeyBindingJws>,
        ) = (listOf(jwsFromIssuer.toString()) + filteredDisclosures + keyBinding.toString()).joinToString("~")

    }

}