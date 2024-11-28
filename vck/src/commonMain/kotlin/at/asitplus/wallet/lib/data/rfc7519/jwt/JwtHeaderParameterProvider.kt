package at.asitplus.wallet.lib.data.rfc7519.jwt

import at.asitplus.wallet.lib.data.rfc7519.jwt.headers.JwtContentTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.headers.JwtTypeHeaderParameterSpecification

interface JwtHeaderParameterProvider : JwtContentTypeHeaderParameterSpecification.ParameterProvider,
    JwtTypeHeaderParameterSpecification.ParameterProvider