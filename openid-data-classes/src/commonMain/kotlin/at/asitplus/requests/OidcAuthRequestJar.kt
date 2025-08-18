package at.asitplus.requests

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthnRequestClaims
import at.asitplus.openid.RelyingPartyMetadata

data class OidcAuthRequestJar(
    override val walletNonce: String?,
    override val claims: AuthnRequestClaims?,
    override val clientMetadata: RelyingPartyMetadata?,
    override val clientMetadataUri: String?,
    override val idTokenHint: String?,
    override val requestUriMethod: String?,
    override val idTokenType: String?,
    override val presentationDefinition: PresentationDefinition?
) : OidcAuthRequest, JarAuthRequest, AuthenticationRequest
