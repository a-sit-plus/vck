package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.DurationSecondsIntSerializer
import at.asitplus.wallet.lib.oidc.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
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
     * OID4VCI:
     * OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned.
     * MAY be a JSON string or a JSON object, depending on the Credential format.
     */
    @SerialName("credential")
    val credential: String? = null, // TODO May be a JSON object

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

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialResponseParameters> =
            runCatching { jsonSerializer.decodeFromString<CredentialResponseParameters>(input) }.wrap()
    }

}
