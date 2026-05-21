@file:Suppress("DEPRECATION")

package at.asitplus.dcapi.request

import at.asitplus.openid.RequestParametersFrom

@Deprecated(
    message = "Use RequestParametersFrom.DcApiRequest instead.",
    replaceWith = ReplaceWith(
        expression = "RequestParametersFrom.DcApiRequest",
        imports = ["at.asitplus.openid.RequestParametersFrom"]
    ),
    level = DeprecationLevel.WARNING
)
typealias DCAPIWalletRequest = RequestParametersFrom.DcApiRequest

@Deprecated(
    message = "Use RequestParametersFrom.OpenId4VpSigned instead.",
    replaceWith = ReplaceWith(
        expression = "RequestParametersFrom.OpenId4VpSigned",
        imports = ["at.asitplus.openid.RequestParametersFrom"]
    ),
    level = DeprecationLevel.WARNING
)
typealias DCAPIWalletOpenId4VpSigned = RequestParametersFrom.OpenId4VpSigned

@Deprecated(
    message = "Use RequestParametersFrom.OpenId4VpMultiSigned instead.",
    replaceWith = ReplaceWith(
        expression = "RequestParametersFrom.OpenId4VpMultiSigned",
        imports = ["at.asitplus.openid.RequestParametersFrom"]
    ),
    level = DeprecationLevel.WARNING
)
typealias DCAPIWalletOpenId4VpMultiSigned = RequestParametersFrom.OpenId4VpMultiSigned

@Deprecated(
    message = "Use RequestParametersFrom.OpenId4VpUnsigned instead.",
    replaceWith = ReplaceWith(
        expression = "RequestParametersFrom.OpenId4VpUnsigned",
        imports = ["at.asitplus.openid.RequestParametersFrom"]
    ),
    level = DeprecationLevel.WARNING
)
typealias DCAPIWalletOpenId4VpUnsigned = RequestParametersFrom.OpenId4VpUnsigned

@Deprecated(
    message = "Use RequestParametersFrom.IsoMdoc instead.",
    replaceWith = ReplaceWith(
        expression = "RequestParametersFrom.IsoMdoc",
        imports = ["at.asitplus.openid.RequestParametersFrom"]
    ),
    level = DeprecationLevel.WARNING
)
typealias DCAPIWalletIsoMdoc = RequestParametersFrom.IsoMdoc