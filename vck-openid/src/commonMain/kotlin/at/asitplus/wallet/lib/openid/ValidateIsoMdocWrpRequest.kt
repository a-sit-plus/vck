package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator

/** Validates reader authentication using the DC API session transcript bound to this request and calling origin. */
suspend fun RequestParametersFrom.IsoMdocDcApi.validateWrpAuthenticationRequest() =
    WrpAuthenticationRequestValidator(this, IsoMdocDcapiResponseBuilder.sessionTranscriptFor(this))
