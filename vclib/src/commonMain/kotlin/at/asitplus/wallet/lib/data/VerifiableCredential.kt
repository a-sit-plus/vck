package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.VcDataModelConstants.REVOCATION_LIST_2020
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.Polymorphic
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

/**
 * The core of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/): a credential.
 */
@Serializable
data class VerifiableCredential(
    @SerialName("id")
    val id: String,
    @SerialName("type")
    val type: Array<String>,
    @SerialName("issuer")
    val issuer: String,
    @Serializable(with = InstantStringSerializer::class)
    @SerialName("issuanceDate")
    val issuanceDate: Instant,
    @Serializable(with = NullableInstantStringSerializer::class)
    @SerialName("expirationDate")
    val expirationDate: Instant?,
    @SerialName("credentialStatus")
    val credentialStatus: CredentialStatus? = null,
    @Polymorphic
    @SerialName("credentialSubject")
    val credentialSubject: CredentialSubject,
) {
    constructor(
        id: String,
        issuer: String,
        lifetime: Duration,
        credentialStatus: CredentialStatus,
        credentialSubject: CredentialSubject,
        credentialType: String,
        issuanceDate: Instant = Clock.System.now(),
        expirationDate: Instant? = Clock.System.now() + lifetime,
    ) : this(
        id = id,
        type = arrayOf(VERIFIABLE_CREDENTIAL, credentialType),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        credentialStatus = credentialStatus,
        credentialSubject = credentialSubject,
    )

    constructor(
        id: String,
        issuer: String,
        issuanceDate: Instant,
        expirationDate: Instant?,
        credentialStatus: CredentialStatus,
        credentialSubject: CredentialSubject,
        credentialType: String,
    ) : this(
        id = id,
        type = arrayOf(VERIFIABLE_CREDENTIAL, credentialType),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        credentialStatus = credentialStatus,
        credentialSubject = credentialSubject,
    )

    constructor(
        id: String,
        issuer: String,
        issuanceDate: Instant,
        lifetime: Duration,
        credentialSubject: RevocationListSubject,
    ) : this(
        id = id,
        type = arrayOf(VERIFIABLE_CREDENTIAL, REVOCATION_LIST_2020),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = issuanceDate + lifetime,
        credentialStatus = null,
        credentialSubject = credentialSubject,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VerifiableCredential

        if (id != other.id) return false
        if (!type.contentEquals(other.type)) return false
        if (issuer != other.issuer) return false
        if (issuanceDate != other.issuanceDate) return false
        if (expirationDate != other.expirationDate) return false
        if (credentialStatus != other.credentialStatus) return false
        return credentialSubject == other.credentialSubject
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + type.contentHashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + issuanceDate.hashCode()
        result = 31 * result + (expirationDate?.hashCode() ?: 0)
        result = 31 * result + (credentialStatus?.hashCode() ?: 0)
        result = 31 * result + credentialSubject.hashCode()
        return result
    }
}
