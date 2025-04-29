package at.asitplus.wallet.lib

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.agent.Parser
import at.asitplus.wallet.lib.agent.VerifiableCredentialJwsInputValidator
import at.asitplus.wallet.lib.agent.VerifiableCredentialJwsStructureValidator
import at.asitplus.wallet.lib.agent.VerifiableCredentialJwsTimelinessValidator
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.*
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A messy dependency injection implementation with all in one place.
 * TODO: Use a dependency injection library like Koin?
 */
open class Configuration {
    open val verifierJwsService: VerifierJwsService
        get() = DefaultVerifierJwsService()

    open val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun
        get() = VerifyJwsSignatureWithCnf()

    open val verifierCoseService: VerifierCoseService
        get() = DefaultVerifierCoseService()

    open val verifyJwsObjectFun: VerifyJwsObjectFun
        get() = VerifyJwsObject()

    open val verifyStatusListTokenPayloadCoseSignatureWithKey: VerifyCoseSignatureFun<StatusListTokenPayload>
        get() = VerifyCoseSignature()

    open val verifiableCredentialJwsStructureValidator: VerifiableCredentialJwsStructureValidator
        get() = VerifiableCredentialJwsStructureValidator()

    open val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator
        get() = VerifiableCredentialJwsTimelinessValidator(
            timeLeeway = timeLeeway,
            clock = clock,
        )

    open val verifiableCredentialJwsInputValidator: VerifiableCredentialJwsInputValidator
        get() = VerifiableCredentialJwsInputValidator(
            verifiableCredentialJwsStructureValidator = verifiableCredentialJwsStructureValidator,
            verifiableCredentialJwsTimelinessValidator = verifiableCredentialJwsTimelinessValidator,
            verifyJwsObject = verifyJwsObjectFun,
            checkRevocationStatus = {
                runCatching {
                    val resolver = tokenStatusResolver
                        ?: throw IllegalStateException("Missing configuration: tokenStatusResolver")
                    resolver(it)
                }.wrap()
            },
        )

    open val parser: Parser
        get() = Parser(
            clock = clock,
            timeLeewaySeconds = timeLeeway.inWholeSeconds,
        )

    open val clock: Clock
        get() = Clock.System

    open val timeLeeway: Duration
        get() = 300.seconds

    open val tokenStatusResolver: (suspend (Status) -> TokenStatus)?
        get() = { status ->
            val token = statusListTokenResolver(status.statusList.uri)

            val payload = token.validate(
                verifyJwsObject = verifyJwsObjectFun,
                verifyCoseSignature = verifyStatusListTokenPayloadCoseSignatureWithKey,
                statusListInfo = status.statusList,
                isInstantInThePast = {
                    it < clock.now()
                },
            ).getOrThrow()

            StatusListTokenValidator.extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = status.statusList,
                zlibService = zlibService,
            ).getOrThrow()
        }

    open val statusListTokenResolver: (suspend (UniformResourceIdentifier) -> StatusListToken)
        get() = {
            throw IllegalStateException("Missing: `statusListTokenResolver`")
        }

    open val zlibService: ZlibService
        get() = DefaultZlibService()

    companion object {
        var instance = Configuration()
    }
}