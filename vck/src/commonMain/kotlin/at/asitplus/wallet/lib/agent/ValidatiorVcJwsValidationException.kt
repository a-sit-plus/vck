@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult

@Deprecated(
    "Validate with at.asitplus.wallet.lib.validation.CredentialValidator, whose report holds every check. " +
            "To be removed in the next major release."
)
class ValidatiorVcJwsValidationException(
    @Suppress("CanBeParameter")
    val validationResult: VcJwsInputValidationResult
) : Throwable(validationResult.toString())