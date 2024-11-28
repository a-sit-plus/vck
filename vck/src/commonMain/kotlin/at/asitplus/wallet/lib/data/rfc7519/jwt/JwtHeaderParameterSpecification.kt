package at.asitplus.wallet.lib.data.rfc7519.jwt

import at.asitplus.wallet.lib.data.rfc7519.jose.JoseHeaderParameterSpecification

interface JwtHeaderParameterSpecification : JoseHeaderParameterSpecification {
    companion object {
        val JoseHeaderParameterSpecification.Companion.JwtHeaderParameterSpecifications: Companion
            get() = Companion
    }
}