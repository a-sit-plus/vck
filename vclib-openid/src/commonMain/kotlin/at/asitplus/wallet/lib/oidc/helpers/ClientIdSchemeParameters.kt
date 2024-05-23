package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import kotlinx.serialization.Serializable

@Serializable
sealed class ClientIdSchemeParameters {

    @Serializable
    data class OtherClientIdSchemeParameters(val clientIdScheme: OpenIdConstants.ClientIdScheme) :
        ClientIdSchemeParameters()

    @Serializable
    sealed class X509ClientIdSchemeParameters : ClientIdSchemeParameters() {

        @Serializable
        data class X509SanDnsClientIdSchemeParameters(val leaf: X509Certificate) :
            X509ClientIdSchemeParameters()

        @Serializable
        data class X509SanUriClientIdSchemeParameters(val leaf: X509Certificate) :
            X509ClientIdSchemeParameters()
    }
}