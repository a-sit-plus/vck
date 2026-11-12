package at.asitplus.wallet.lib.data

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.IssuerSigned
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.validation.ValidatedCredential
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Instant

/**
 * The claims of a credential as JSON, on which OpenID4VP selects the claims to present with claims path pointers
 * (OpenID4VP 1.0, 7).
 */
object CredentialToJsonConverter {

    fun toJsonElement(credential: SubjectCredentialStore.StoreEntry): JsonElement = when (credential) {
        is SubjectCredentialStore.StoreEntry.Vc -> toJsonElement(credential.vc)

        // The claims as RFC 9901, 7.1 processes them, so that the positions DCQL selects are those of
        // SdJwtDecoded.disclosuresByPath, from which the disclosures to present are taken
        is SubjectCredentialStore.StoreEntry.SdJwt -> catchingUnwrapped {
            credential.decoded.reconstructedJsonObject
        }.getOrElse {
            Napier.w("SD-JWT can not be processed, it has no claims to match", it)
            JsonObject(emptyMap())
        }

        is SubjectCredentialStore.StoreEntry.Iso -> credential.issuerSigned.toJsonObject()
    }

    /**
     * The claims of a validated credential, e.g. to display them: the reconstructed claims of an SD-JWT VC, the
     * root of the VC of a VC-JWT as in [toJsonElement], and the elements of an ISO mdoc by namespace.
     */
    fun toJsonElement(credential: ValidatedCredential): JsonObject = when (credential) {
        is ValidatedCredential.SdJwtVc -> credential.decoded.reconstructedJsonObject
        is ValidatedCredential.VcJwt -> toJsonElement(credential.credential)
        is ValidatedCredential.IsoMdoc -> credential.issuerSigned.toJsonObject()
    }

    private fun IssuerSigned.toJsonObject() = buildJsonObject {
        namespaces?.forEach {
            put(it.key, buildJsonObject {
                it.value.entries.map { it.value }.forEach { value ->
                    put(value.elementIdentifier, value.elementValue.toJsonElement())
                }
            })
        }
    }

    /**
     * The root of the W3C VC, i.e. the `vc` claim of the JWT (W3C VC Data Model 1.1, 6.3.1), which DCQL claims paths
     * "always match on" for W3C VCs (OpenID4VP 1.0, B.1.2), e.g. `["credentialSubject", "given_name"]`.
     */
    fun toJsonElement(verifiableCredentialJws: VerifiableCredentialJws): JsonObject =
        joseCompliantSerializer.encodeToJsonElement(verifiableCredentialJws.vc).jsonObject

    /**
     * Converts any value to a [JsonElement], to be used when serializing values into JSON structures. A value of a type
     * without a known encoding is converted to the string of [toString], see [toJsonElementOrNull].
     */
    fun Any.toJsonElement(): JsonElement = toJsonElementOrNull() ?: JsonPrimitive(toString())

    /**
     * Converts a value to a [JsonElement] like [toJsonElement], or returns null if its type has no known encoding,
     * i.e. it is neither one of the types handled here nor encoded by a [JsonCredentialSerializer]. Use this where a
     * value must not be represented by its [toString], e.g. when matching it against the `values` of a DCQL claims
     * query (OpenID4VP 1.0, 6.3).
     */
    fun Any.toJsonElementOrNull(): JsonElement? = when (this) {
        is Boolean -> JsonPrimitive(this)
        is Number -> JsonPrimitive(this)
        is String -> JsonPrimitive(this)
        is ByteArray -> JsonPrimitive(encodeToString(Base64UrlStrict))
        is LocalDate -> joseCompliantSerializer.encodeToJsonElement(this)
        is Instant -> joseCompliantSerializer.encodeToJsonElement(this)
        is LocalDateOrInstant -> joseCompliantSerializer.encodeToJsonElement(this)
        is UByte -> JsonPrimitive(this)
        is UShort -> JsonPrimitive(this)
        is UInt -> JsonPrimitive(this)
        is ULong -> JsonPrimitive(this)
        is Collection<*> -> JsonArray(mapNotNull { it?.toJsonElement() }.toList())
        is Array<*> -> JsonArray(mapNotNull { it?.toJsonElement() }.toList())
        is JsonElement -> this
        else -> JsonCredentialSerializer.encode(this)
    }
}

fun SelectiveDisclosureItem.Companion.fromAnyValue(salt: ByteArray, claimName: String?, claimValue: Any) =
    SelectiveDisclosureItem(salt, claimName, claimValue.toJsonElement())