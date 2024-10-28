package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import io.github.aakira.napier.Napier

/**
 * Representation of a signed SD-JWT,
 * as issued by an [at.asitplus.wallet.lib.agent.Issuer] or presented by an [at.asitplus.wallet.lib.agent.Holder], i.e.
 * consisting of an JWS (with header, payload is [at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt] and signature)
 * and several disclosures ([SelectiveDisclosureItem]) separated by a `~`,
 * possibly ending with a [keyBindingJws], that is a JWS with payload [KeyBindingJws].
 */
data class SdJwtSigned(
    val jws: JwsSigned,
    val rawDisclosures: List<String>,
    val keyBindingJws: JwsSigned? = null,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SdJwtSigned

        if (jws != other.jws) return false
        if (rawDisclosures != other.rawDisclosures) return false
        if (keyBindingJws != other.keyBindingJws) return false

        return true
    }

    override fun hashCode(): Int {
        var result = jws.hashCode()
        result = 31 * result + rawDisclosures.hashCode()
        result = 31 * result + (keyBindingJws?.hashCode() ?: 0)
        return result
    }

    fun getPayloadAsVerifiableCredentialSdJwt(): KmmResult<VerifiableCredentialSdJwt> =
        VerifiableCredentialSdJwt.deserialize(jws.payload.decodeToString())

    companion object {
        fun parse(input: String): SdJwtSigned? {
            if (!input.contains("~"))
                return null.also { Napier.w("Could not parse SD-JWT: $input") }
            val stringList = input.replace("[^A-Za-z0-9-_.~]".toRegex(), "").split("~")
            if (stringList.isEmpty())
                return null.also { Napier.w("Could not parse SD-JWT: $input") }
            val jws = JwsSigned.deserialize(stringList.first()).getOrNull()
                ?: return null.also { Napier.w("Could not parse JWS from SD-JWT: $input") }
            val stringListWithoutJws = stringList.drop(1)
            val rawDisclosures = stringListWithoutJws
                .filterNot { it.contains(".") }
                .filterNot { it.isEmpty() }
            val keyBindingString = stringList.drop(1 + rawDisclosures.size).firstOrNull()
            val keyBindingJws = keyBindingString?.let { JwsSigned.deserialize(it).getOrNull() }
            return SdJwtSigned(jws, rawDisclosures, keyBindingJws)
        }

        fun serializePresentation(
            jwsFromIssuer: JwsSigned,
            filteredDisclosures: Set<String>,
            keyBinding: JwsSigned
        ) = (listOf(jwsFromIssuer.serialize()) + filteredDisclosures + keyBinding.serialize()).joinToString("~")

        fun sdHashInput(
            validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
            filteredDisclosures: Set<String>
        ) = (listOf(validSdJwtCredential.vcSerialized.substringBefore("~")) + filteredDisclosures)
            .joinToString("~", postfix = "~")
    }

}