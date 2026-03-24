package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val StatusListTokenTypeValidationTest by testSuite {
    "jwt status list token type validation" - {
        "accepts typ=statuslist+jwt" {
            val issued = StatusListAgent().issueStatusListJwt()
            val statusListToken = StatusListJwt(issued, resolvedAt = null)

            statusListToken.validate(
                verifyJwsObject = { KmmResult.success(Verifier.Success) },
                revocationListInfo = StatusListInfo(
                    index = 0u,
                    uri = issued.getPayload<StatusListTokenPayload>().getOrThrow().subject
                ),
                isInstantInThePast = { false },
            ).isSuccess shouldBe true
        }

        "rejects typ=application/statuslist+jwt" {
            //TODO .copy is now internal in JwsCompact
//            val issued = StatusListAgent().issueStatusListJwt()
//            val statusListToken = StatusListJwt(
//                value = issued.copy(
//                    header = issued.jwsHeader.copy(type = MediaTypes.Application.STATUSLIST_JWT)
//                ),
//                resolvedAt = null,
//            )
//
//            statusListToken.validate(
//                verifyJwsObject = { KmmResult.success(Verifier.Success) },
//                revocationListInfo = StatusListInfo(index = 0u, uri = issued.payload.subject),
//                isInstantInThePast = { false },
//            ).exceptionOrNull().toString().shouldContain("Invalid type header")
        }
    }
}
