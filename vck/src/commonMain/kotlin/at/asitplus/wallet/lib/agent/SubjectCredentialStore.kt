package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.iso.IssuerSigned
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Stores all credentials that a subject has received
 */
interface SubjectCredentialStore {

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialJws]
     * @param vcSerialized Serialized form of [VerifiableCredential]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialJws,
        vcSerialized: String,
        scheme: ConstantIndex.CredentialScheme,
    ) : StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param vc Instance of [VerifiableCredentialSdJwt]
     * @param vcSerialized Serialized form of [at.asitplus.wallet.lib.jws.SdJwtSigned]
     */
    suspend fun storeCredential(
        vc: VerifiableCredentialSdJwt,
        vcSerialized: String,
        disclosures: Map<String, SelectiveDisclosureItem?>,
        scheme: ConstantIndex.CredentialScheme,
    ) : StoreEntry

    /**
     * Implementations should store the passed credential in a secure way.
     * Passed credentials have been validated before.
     *
     * @param issuerSigned Instance of [IssuerSigned] (an ISO credential)
     */
    suspend fun storeCredential(
        issuerSigned: IssuerSigned,
        scheme: ConstantIndex.CredentialScheme,
    ) : StoreEntry

    /**
     * Return all stored credentials.
     * Selective Disclosure: Specify list of credential schemes in [credentialSchemes].
     */
    suspend fun getCredentials(credentialSchemes: Collection<ConstantIndex.CredentialScheme>? = null)
            : KmmResult<List<StoreEntry>>

    @Serializable
    sealed interface StoreEntry {
        val schemaUri: String
        val scheme: ConstantIndex.CredentialScheme?
            get() = AttributeIndex.resolveSchemaUri(schemaUri)

        @Serializable
        data class Vc(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("vc")
            val vc: VerifiableCredentialJws,
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry

        @Serializable
        data class SdJwt(
            @SerialName("vc-serialized")
            val vcSerialized: String,
            @SerialName("sd-jwt")
            val sdJwt: VerifiableCredentialSdJwt,
            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            @SerialName("disclosures")
            val disclosures: Map<String, SelectiveDisclosureItem?>,
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry

        @Serializable
        data class Iso(
            @SerialName("issuer-signed")
            val issuerSigned: IssuerSigned,
            @SerialName("schema-uri")
            override val schemaUri: String,
        ) : StoreEntry
    }
}