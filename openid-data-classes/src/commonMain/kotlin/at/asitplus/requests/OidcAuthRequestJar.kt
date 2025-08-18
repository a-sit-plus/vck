package at.asitplus.requests

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthnRequestClaims
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.TransactionDataBase64Url
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class OidcAuthRequestJar(
    override val clientId: String,
    override val walletNonce: String? = null,
    override val claims: AuthnRequestClaims? = null,
    override val clientMetadata: RelyingPartyMetadata? = null,
    override val clientMetadataUri: String? = null,
    override val idTokenHint: String? = null,
    override val requestUriMethod: String? = null,
    override val idTokenType: String? = null,
    override val presentationDefinition: PresentationDefinition? = null,
    override val request: String? = null,
    override val requestUri: String? = null,
    override val transactionData: List<TransactionDataBase64Url>? = null,
    override val issuer: String? = null,
    override val audience: String? = null,
    override val issuedAt: Instant? = null,
    override val responseUrl: String? = null,
    override val nonce: String? = null,
    override val state: String? = null,
) : OidcAuthRequest, JarAuthRequest
