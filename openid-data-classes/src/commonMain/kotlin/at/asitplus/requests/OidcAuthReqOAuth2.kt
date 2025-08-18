package at.asitplus.requests

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthnRequestClaims
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.RelyingPartyMetadata

data class OidcAuthReqOAuth2(
    override val walletNonce: String?,
    override val claims: AuthnRequestClaims?,
    override val clientMetadata: RelyingPartyMetadata?,
    override val clientMetadataUri: String?,
    override val idTokenHint: String?,
    override val requestUriMethod: String?,
    override val idTokenType: String?,
    override val presentationDefinition: PresentationDefinition?,
    override val clientId: String,
    override val responseType: String,
    override val redirectUri: String?,
    override val scope: String?,
    override val state: String?,
    override val authorizationDetails: List<AuthorizationDetails>?,
    override val codeChallenge: String?,
    override val codeChallengeMethod: String?
) : OidcAuthRequest, OAuth2AuthRequest, AuthenticationRequest