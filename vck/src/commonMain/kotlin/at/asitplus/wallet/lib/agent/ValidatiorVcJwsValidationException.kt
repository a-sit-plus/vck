package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult

class ValidatiorVcJwsValidationException(
    @Suppress("CanBeParameter")
    val validationResult: VcJwsInputValidationResult
) : Throwable(validationResult.toString())