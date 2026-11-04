package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.validation.RelyingPartyValidationResult
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.ValidationPolicy

/**
 * Validates the relying party of this request with [validator] under [policy], authenticating it over the DC API
 * session transcript bound to this request and calling origin.
 */
suspend fun RequestParametersFrom.IsoMdocDcApi.validateRelyingParty(
    validator: RelyingPartyValidator,
    policy: ValidationPolicy,
): RelyingPartyValidationResult =
    validator.validate(this, IsoMdocDcapiResponseBuilder.sessionTranscriptFor(this), policy)
