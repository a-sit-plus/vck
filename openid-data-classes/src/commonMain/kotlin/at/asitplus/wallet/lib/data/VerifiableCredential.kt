package at.asitplus.wallet.lib.data

import at.asitplus.openid.truncateToSeconds
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo

import kotlin.time.Instant
import kotlinx.serialization.Polymorphic
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration

/**
 * The core of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/): a credential.
 */
@Serializable
data class VerifiableCredential(
    @SerialName("id")
    val id: String,
    @SerialName("type")
    val type: Collection<String>,
    @SerialName("issuer")
    val issuer: String,
    @Serializable(with = InstantStringSerializer::class)
    @SerialName("issuanceDate")
    val issuanceDate: Instant,
    @Serializable(with = NullableInstantStringSerializer::class)
    @SerialName("expirationDate")
    val expirationDate: Instant?,
    @SerialName("status")
    @Serializable(with = RevocationListInfo.StatusSurrogateSerializer::class)
    val credentialStatus: RevocationListInfo? = null,
    @Polymorphic
    @SerialName("credentialSubject")
    val credentialSubject: CredentialSubject,
) {
    constructor(
        id: String,
        issuer: String,
        lifetime: Duration,
        credentialStatus: RevocationListInfo,
        credentialSubject: CredentialSubject,
        credentialType: String,
        issuanceDate: Instant = Clock.System.now().truncateToSeconds(),
        expirationDate: Instant? = issuanceDate + lifetime,
    ) : this(
        id = id,
        type = listOf(VERIFIABLE_CREDENTIAL, credentialType),
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
        credentialStatus: RevocationListInfo,
        credentialSubject: CredentialSubject,
        credentialType: String,
    ) : this(
        id = id,
        type = listOf(VERIFIABLE_CREDENTIAL, credentialType),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = expirationDate,
        credentialStatus = credentialStatus,
        credentialSubject = credentialSubject,
    )
}