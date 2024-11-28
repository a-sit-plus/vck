package at.asitplus.wallet.lib.data.rfc7516.jwe.headers

import at.asitplus.wallet.lib.data.rfc7519.jose.JoseHeaderParameterSpecification

interface JweHeaderParameterSpecification : JoseHeaderParameterSpecification {
    companion object {
        val JoseHeaderParameterSpecification.Companion.JweHeaderParameterSpecifications: Companion
            get() = Companion
    }
}