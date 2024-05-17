package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import kotlinx.serialization.Serializable

@Serializable
sealed interface ClientIdSchemeParameters {
    val clientIdScheme: OpenIdConstants.ClientIdScheme

    @Serializable
    class OtherClientIdSchemeParameters(override val clientIdScheme: OpenIdConstants.ClientIdScheme) :
        ClientIdSchemeParameters

    @Serializable
    sealed interface X509ClientIdSchemeParameters : ClientIdSchemeParameters {
        val leaf: X509Certificate

        @Serializable
        class X509SanDnsClientIdSchemeParameters(override val leaf: X509Certificate) :
            X509ClientIdSchemeParameters {
            override val clientIdScheme: OpenIdConstants.ClientIdScheme
                get() = OpenIdConstants.ClientIdScheme.X509_SAN_DNS
        }

        @Serializable
        class X509SanUriClientIdSchemeParameters(override val leaf: X509Certificate) :
            X509ClientIdSchemeParameters {
            override val clientIdScheme: OpenIdConstants.ClientIdScheme
                get() = OpenIdConstants.ClientIdScheme.X509_SAN_URI
        }
    }
}