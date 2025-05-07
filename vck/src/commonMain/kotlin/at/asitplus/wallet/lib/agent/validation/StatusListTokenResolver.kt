package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import kotlin.time.Clock

fun interface StatusListTokenResolver {
    suspend operator fun invoke(statusListUrl: UniformResourceIdentifier): StatusListToken

    fun toTokenStatusResolver(
        clock: Clock = Clock.System,
        zlibService: ZlibService = DefaultZlibService(),
        verifyJwsObjectIntegrity: VerifyJwsObjectFun = VerifyJwsObject(),
        verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
    ) = TokenStatusResolver { status ->
        runCatching {
            val token = this(status.statusList.uri)

            val payload = token.validate(
                verifyJwsObject = verifyJwsObjectIntegrity,
                verifyCoseSignature = verifyCoseSignature,
                statusListInfo = status.statusList,
                isInstantInThePast = {
                    it < kotlinx.datetime.Instant.fromEpochMilliseconds(clock.now().toEpochMilliseconds())
                },
            ).getOrThrow()

            StatusListTokenValidator.extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = status.statusList,
                zlibService = zlibService,
            ).getOrThrow()
        }.wrap()
    }
}