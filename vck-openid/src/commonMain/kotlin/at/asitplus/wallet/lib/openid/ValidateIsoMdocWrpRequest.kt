package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator
import at.asitplus.wallet.lib.validation.RelyingPartyValidationResult
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.ValidationPolicy

/** Validates reader authentication using the DC API session transcript bound to this request and calling origin. */
@Deprecated(
    "Validate the relying party with validateRelyingParty(validator, policy). To be removed in the next major release.",
    ReplaceWith("validateRelyingParty(validator, policy)"),
)
@Suppress("DEPRECATION")
suspend fun RequestParametersFrom.IsoMdocDcApi.validateWrpAuthenticationRequest() =
    WrpAuthenticationRequestValidator(this, IsoMdocDcapiResponseBuilder.sessionTranscriptFor(this))

/**
 * Validates the relying party of this request with [validator] under [policy], authenticating it over the DC API
 * session transcript bound to this request and calling origin.
 */
suspend fun RequestParametersFrom.IsoMdocDcApi.validateRelyingParty(
    validator: RelyingPartyValidator,
    policy: ValidationPolicy,
): RelyingPartyValidationResult =
    validator.validate(this, IsoMdocDcapiResponseBuilder.sessionTranscriptFor(this), policy)
