package at.asitplus.wallet.lib.data

import kotlin.time.Clock
import kotlin.time.Instant
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
        credentialType: String = ConstantIndex.Generic.vcType,
        issuanceDate: Instant = Clock.System.now(),
        expirationDate: Instant? = Clock.System.now() + lifetime,
    ) : this(
        id = id,
        type = arrayOf("VerifiableCredential", credentialType),
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
        credentialType: String = ConstantIndex.Generic.vcType,
    ) : this(
        id = id,
        type = arrayOf("VerifiableCredential", credentialType),
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
        type = arrayOf("VerifiableCredential", "RevocationList2020"),
        issuer = issuer,
        issuanceDate = issuanceDate,
        expirationDate = issuanceDate + lifetime,
        credentialStatus = null,
        credentialSubject = credentialSubject,
    )

    fun toJws() = VerifiableCredentialJws(
        vc = this,
        subject = credentialSubject.id,
        notBefore = issuanceDate,
        issuer = issuer,
        expiration = expirationDate,
        jwtId = id
    )
}
