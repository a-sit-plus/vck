package at.asitplus.wallet.lib.data.rfc7519.jwe

import at.asitplus.wallet.lib.data.rfc7519.jwe.headers.JweAudienceHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwe.headers.JweIssuerHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwe.headers.JweSubjectHeaderParameterSpecification

interface JweHeaderParameterProvider : JweAudienceHeaderParameterSpecification.ParameterProvider,
    JweIssuerHeaderParameterSpecification.ParameterProvider,
    JweSubjectHeaderParameterSpecification.ParameterProvider