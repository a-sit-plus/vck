package at.asitplus.requests

import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class CscAuthRequestJar(
    override val credentialID: ByteArray?,
    override val signatureQualifier: SignatureQualifier?,
    override val numSignatures: Int?,
    override val hashes: Hashes?,
    @Serializable(ObjectIdentifierStringSerializer::class)
    override val hashAlgorithmOid: ObjectIdentifier?,
    override val description: String?,
    override val accountToken: JsonWebToken?,
    override val clientData: String?,
    override val lang: String?,
    override val issuer: String?,
    override val audience: String?,
    override val issuedAt: Instant?,
    override val request: String?,
    override val requestUri: String?,
    override val clientId: String,
) : CscAuthRequest, JarAuthRequest
