package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * Representation of a signed SD-JWT,
 * as issued by an issuer or presented by a holder, i.e.
 * consisting of an JWS (with header, payload is [at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt] and signature)
 * and several disclosures ([at.asitplus.wallet.lib.data.SelectiveDisclosureItem]) separated by a `~`,
 * possibly ending with a [keyBindingJws], that is a JWS with payload [at.asitplus.wallet.lib.data.KeyBindingJws].
 */
data class SdJwtSigned(
    val jws: JwsSigned<JsonElement>,
    val rawDisclosures: List<String>,
    val keyBindingJws: JwsSigned<KeyBindingJws>? = null,
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

    fun getPayloadAsVerifiableCredentialSdJwt(): KmmResult<VerifiableCredentialSdJwt> =
        catching { joseCompliantSerializer.decodeFromJsonElement<VerifiableCredentialSdJwt>(jws.payload) }

    fun getPayloadAsJsonObject(): KmmResult<JsonObject> =
        catching { jws.payload as JsonObject }

    /**
     * Compact serialization: JWT in JWS compact serialization (Base64-URL with dots),
     * disclosures and key binding appended, separated by a tilde.
     */
    fun serialize() = keyBindingJws?.let {
        serializePresentation(jws, rawDisclosures.toSet(), it)
    } ?: (listOf(jws.serialize()) + rawDisclosures).joinToString("~", postfix = "~")

    override fun toString(): String {
        return "SdJwtSigned(jws=${jws.serialize()}, " +
                "rawDisclosures=$rawDisclosures, " +
                "keyBindingJws=${keyBindingJws?.serialize()}, " +
                "hashInput='$hashInput')"
    }

    companion object {
        fun issued(
            jws: JwsSigned<JsonElement>,
            disclosures: List<String>,
        ) = SdJwtSigned(
            jws = jws,
            rawDisclosures = disclosures,
            keyBindingJws = null,
            hashInput = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
        )

        fun presented(
            jws: JwsSigned<JsonElement>,
            disclosures: Set<String>,
            keyBinding: JwsSigned<KeyBindingJws>,
        ) = SdJwtSigned(
            jws = jws,
            rawDisclosures = disclosures.toList(),
            keyBindingJws = keyBinding,
            hashInput = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
        )

        fun parseCatching(input: String): KmmResult<SdJwtSigned> = catching {
            require(input.contains("~")) { "Could not parse SD-JWT: $input" }
            val stringList = input.replace("[^A-Za-z0-9-_.~]".toRegex(), "").split("~")
            require(stringList.isNotEmpty()) { "Could not parse SD-JWT: $input" }
            val jws = JwsSigned.deserialize<JsonElement>(
                deserializationStrategy = JsonElement.serializer(),
                it = stringList.first(),
                json = joseCompliantSerializer
            ).getOrThrow()
            val stringListWithoutJws = stringList.drop(1)
            val rawDisclosures = stringListWithoutJws
                .filterNot { it.contains(".") }
                .filterNot { it.isEmpty() }
            val keyBindingString = stringList.drop(1 + rawDisclosures.size).firstOrNull()
            val keyBindingJws = keyBindingString?.takeIf { it.isNotEmpty() }?.let {
                JwsSigned.deserialize<KeyBindingJws>(
                    deserializationStrategy = KeyBindingJws.serializer(),
                    it = it,
                    json = joseCompliantSerializer
                ).getOrThrow()
            }
            val hashInput = input.substringBeforeLast("~") + "~"
            SdJwtSigned(jws, rawDisclosures, keyBindingJws, hashInput)
        }

        /**
         * Compact serialization: JWT in JWS compact serialization (Base64-URL with dots),
         * disclosures and key binding appended, separated by a tilde.
         */
        fun serializePresentation(
            jwsFromIssuer: JwsSigned<*>,
            filteredDisclosures: Set<String>,
            keyBinding: JwsSigned<KeyBindingJws>,
        ) = (listOf(jwsFromIssuer.serialize()) + filteredDisclosures + keyBinding.serialize()).joinToString("~")

    }

}