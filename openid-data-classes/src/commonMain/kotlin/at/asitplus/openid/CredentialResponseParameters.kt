package at.asitplus.openid

import at.asitplus.catchingUnwrapped
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration

@Serializable
data class CredentialResponseParameters(

    /**
     * OID4VCI: Contains an array of one or more issued Credentials. It MUST NOT be used if the [transactionId]
     * parameter is present. The elements of the array MUST be objects.
     */
    @SerialName("credentials")
    val credentials: Set<CredentialResponseSingleCredential>? = null,

    /**
     * OID4VCI: OPTIONAL. String identifying a Deferred Issuance transaction. This parameter is contained in the
     * response if the Credential Issuer cannot immediately issue the Credential. The value is subsequently used to
     * obtain the respective Credential with the Deferred Credential Endpoint (see Section 9). It MUST not be used if
     * the [credentials] parameter is present. It MUST be invalidated after the Credential for which it was meant has
     * been obtained by the Wallet.
     */
    @SerialName("transaction_id")
    val transactionId: String? = null,

    /**
     * OID4VCI: REQUIRED if [transactionId] is present. Contains a positive number that represents the minimum amount
     * of time in seconds that the Wallet SHOULD wait after receiving the response before sending a new request to the
     * Deferred Credential Endpoint. It MUST NOT be used if the [credentials] parameter is present.
     */
    @SerialName("interval")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val interval: Duration? = null,

    /**
     * OID4VCI: OPTIONAL. String identifying one or more Credentials issued in one Credential Response.
     * It MUST be included in the Notification Request as defined in Section 10.1.
     * It MUST not be used if the [credentials] parameter is not present.
     */
    @SerialName("notificationId")
    val notificationId: String? = null,
) {
    fun extractCredentials(): List<String> =
        credentials?.let { it.mapNotNull { it.credentialString } } ?: listOf()
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