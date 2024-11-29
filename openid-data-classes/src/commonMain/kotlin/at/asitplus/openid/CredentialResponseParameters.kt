package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlin.time.Duration

@Serializable
data class CredentialResponseParameters(
    /**
     * OID4VCI:
     * OPTIONAL. JSON string denoting the format of the issued Credential.
     */
    @SerialName("format")
    val format: CredentialFormatEnum? = null,

    /**
     * OID4VCI: OPTIONAL. Contains issued Credential.
     * It MUST NOT be used if [credentials] or [transactionId] parameter is present.
     * It MAY be a string or an object, depending on the Credential Format.
     * See Appendix A for the Credential Format-specific encoding requirements.
     */
    @SerialName("credential")
    val credential: String? = null, // TODO May be a JSON element

    /**
     * OID4VCI: OPTIONAL. Contains an array of issued Credentials.
     * It MUST NOT be used if [credential] or [transactionId] parameter is present.
     * The values in the array MAY be a string or an object, depending on the Credential Format.
     * See Appendix A for the Credential Format-specific encoding requirements.
     */
    @SerialName("credentials")
    val credentials: List<JsonElement>? = null,

    /**
     * OID4CI: OPTIONAL. String identifying a Deferred Issuance transaction.
     * This claim is contained in the response if the Credential Issuer cannot immediately issue the Credential.
     * The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint.
     * It MUST not be used if [credential] or [credentials] is present.
     * It MUST be invalidated after the Credential for which it was meant has been obtained by the Wallet.
     */
    @SerialName("transaction_id")
    val transactionId: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a nonce to be used to create a proof of possession of key material when
     * requesting a Credential.
     * When received, the Wallet MUST use this nonce value for its subsequent Credential Requests until the
     * Credential Issuer provides a fresh nonce.
     */
    @SerialName("c_nonce")
    val clientNonce: String? = null,

    /**
     * OID4VCI: OPTIONAL. Number denoting the lifetime in seconds of the [clientNonce].
     */
    @SerialName("c_nonce_expires_in")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val clientNonceExpiresIn: Duration? = null,
) {

    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialResponseParameters> =
            runCatching { odcJsonSerializer.decodeFromString<CredentialResponseParameters>(input) }.wrap()
    }

}
