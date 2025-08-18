package at.asitplus.requests

import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.Serializable

@Serializable(with= AuthenticationRequestSerializer::class)
data class CscAuthRequestJar(
    override val credentialID: ByteArray?,
    override val signatureQualifier: SignatureQualifier?,
    override val numSignatures: Int?,
    override val hashes: Hashes?,
    override val hashAlgorithmOid: ObjectIdentifier?,
    override val description: String?,
    override val accountToken: JsonWebToken?,
    override val clientData: String?,
    override val lang: String?
) : CscAuthRequest, JarAuthRequest, AuthenticationRequest
