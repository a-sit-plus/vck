package at.asitplus.requests

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthnRequestClaims
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.TransactionDataBase64Url
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class OidcAuthRequestJar(
    override val walletNonce: String?,
    override val claims: AuthnRequestClaims?,
    override val clientMetadata: RelyingPartyMetadata?,
    override val clientMetadataUri: String?,
    override val idTokenHint: String?,
    override val requestUriMethod: String?,
    override val idTokenType: String?,
    override val presentationDefinition: PresentationDefinition?,
    override val request: String?,
    override val requestUri: String?,
    override val clientId: String,
    override val transactionData: List<TransactionDataBase64Url>?,
    override val issuer: String?,
    override val audience: String?,
    override val issuedAt: Instant?
) : OidcAuthRequest, JarAuthRequest
