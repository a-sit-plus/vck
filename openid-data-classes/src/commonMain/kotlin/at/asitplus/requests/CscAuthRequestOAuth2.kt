package at.asitplus.requests

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.Serializable

@Serializable
data class CscAuthRequestOAuth2 (
    override val credentialID: ByteArray?,
    override val signatureQualifier: SignatureQualifier?,
    override val numSignatures: Int?,
    override val hashes: Hashes?,
    @Serializable(ObjectIdentifierStringSerializer::class)
    override val hashAlgorithmOid: ObjectIdentifier?,
    override val description: String?,
    override val accountToken: JsonWebToken?,
    override val clientData: String?,
    override val clientId: String,
    override val responseType: String,
    override val redirectUri: String?,
    override val scope: String?,
    override val state: String?,
    override val authorizationDetails: List<AuthorizationDetails>?,
    override val codeChallenge: String?,
    override val codeChallengeMethod: String?,
    override val lang: String?, override val resource: String?
) : CscAuthRequest, OAuth2AuthRequest