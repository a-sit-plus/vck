package at.asitplus.requests

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.Hashes
import at.asitplus.openid.OpenIdConstants
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
    val clientId: String,
    val responseType: String,
    val scope: String?,
    val state: String?,
    val authorizationDetails: List<AuthorizationDetails>?,
    val codeChallenge: String?,
    val codeChallengeMethod: String?,
    override val lang: String?,
    val resource: String?,
    val redirectUrl: String?,
    val responseMode: OpenIdConstants.ResponseMode?
) : CscAuthRequest