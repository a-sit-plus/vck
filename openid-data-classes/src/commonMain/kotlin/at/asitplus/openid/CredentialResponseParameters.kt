package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration

@Serializable
data class CredentialResponseParameters(

    /**
     * OID4VCI: Contains an array of one or more issued Credentials. It MUST NOT be used if the `transaction_id`
     * parameter is present. The elements of the array MUST be objects.
     */
    @SerialName("credentials")
    val credentials: Set<CredentialResponseSingleCredential>? = null,

    /**
     * OID4CI:
     * OPTIONAL. A JSON string containing a security token subsequently used to obtain a Credential. MUST be present
     * when credential is not returned.
     */
    @SerialName("acceptance_token")
    val acceptanceToken: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL. JSON string containing a nonce to be used to create a proof of possession of key material when
     * requesting a Credential. When received, the Wallet MUST use this nonce value for its subsequent credential
     * requests until the Credential Issuer provides a fresh nonce.
     */
    @SerialName("c_nonce")
    val clientNonce: String? = null,

    /**
     * OID4VCI:
     * OPTIONAL. JSON integer denoting the lifetime in seconds of the c_nonce.
     */
    @SerialName("c_nonce_expires_in")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val clientNonceExpiresIn: Duration? = null,
) {
    fun extractCredentials(): List<String> =
        credentials?.let { it.mapNotNull { it.credentialString } } ?: listOf()

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialResponseParameters> =
            catching { odcJsonSerializer.decodeFromString<CredentialResponseParameters>(input) }
    }

}

@Serializable
data class CredentialResponseSingleCredential(
    /**
     * OID4VCI: REQUIRED. Contains one issued Credential. It MAY be a string or an object, depending on the Credential
     * Format. See Appendix A for the Credential Format-specific encoding requirements.
     */
    @SerialName("credential")
    val credential: JsonElement,
) {
    /** Currently, there is no other format defined to transport credentials */
    val credentialString: String? by lazy {
        catchingUnwrapped { credential.jsonPrimitive.content }.getOrNull()
    }
}