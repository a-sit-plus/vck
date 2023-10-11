package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.wallet.lib.data.dif.FormatHolder
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class RelyingPartyMetadata(
    @SerialName("redirect_uris")
    val redirectUris: Array<String>,
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet,

    /**
     * OIDC SIOPv2: REQUIRED. A JSON array of strings representing URI scheme identifiers and optionally method names of
     * supported Subject Syntax Types.
     * Valid values include `urn:ietf:params:oauth:jwk-thumbprint`, `did:example` and others.
     */
    @SerialName("subject_syntax_types_supported")
    val subjectSyntaxTypesSupported: Array<String>,

    /**
     * OID4VP: REQUIRED. An object defining the formats and proof types of Verifiable Presentations and Verifiable
     * Credentials that a Verifier supports. Deployments can extend the formats supported, provided Issuers, Holders
     * and Verifiers all understand the new format.
     */
    @SerialName("vp_formats")
    val vpFormats: FormatHolder? = null,

    /**
     * OID4VP: OPTIONAL. JSON String identifying the Client Identifier scheme. The value range defined by this
     * specification is `pre-registered`, `redirect_uri`, `entity_id`, `did`.
     * If omitted, the default value is `pre-registered`.
     */
    @SerialName("client_id_scheme")
    val clientIdScheme: String? = "pre-registered",

    ) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RelyingPartyMetadata

        if (!redirectUris.contentEquals(other.redirectUris)) return false
        if (jsonWebKeySet != other.jsonWebKeySet) return false
        if (!subjectSyntaxTypesSupported.contentEquals(other.subjectSyntaxTypesSupported)) return false
        if (vpFormats != other.vpFormats) return false
        return clientIdScheme == other.clientIdScheme
    }

    override fun hashCode(): Int {
        var result = redirectUris.contentHashCode()
        result = 31 * result + jsonWebKeySet.hashCode()
        result = 31 * result + subjectSyntaxTypesSupported.contentHashCode()
        result = 31 * result + (vpFormats?.hashCode() ?: 0)
        result = 31 * result + (clientIdScheme?.hashCode() ?: 0)
        return result
    }


    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RelyingPartyMetadata>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}


@Serializable
data class JsonWebKeySet(
    @SerialName("keys")
    val keys: Array<JsonWebKey>,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebKeySet

        if (!keys.contentEquals(other.keys)) return false

        return true
    }

    override fun hashCode(): Int {
        return keys.contentHashCode()
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RelyingPartyMetadata>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}
