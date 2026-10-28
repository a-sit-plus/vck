package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.legacy.JwsHeader
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.jws.patchHeader
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import kotlinx.serialization.json.put
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

val StatusListTokenTypeValidationTest by matrixSuite {
    "jwt status list token type validation" - {
        "accepts typ=statuslist+jwt" {
            val issued = StatusListAgent().issueStatusListJwt()
            val statusListToken = StatusListJwt(issued, resolvedAt = null)

            statusListToken.validate(
                verifyJwsObject = { KmmResult.success(SignatureVerifier.Success) },
                revocationListInfo = StatusListInfo(index = 0u, uri = issued.payload.subject),
                isInstantInThePast = { false },
            ).isSuccess shouldBe true
        }

        "rejects typ=application/statuslist+jwt" {
            val issued = StatusListAgent().issueStatusListJwt()
            val statusListToken = StatusListJwt(
                value = issued.raw.patchHeader {
                    put("typ", MediaTypes.Application.STATUSLIST_JWT)
                }.typed<JwsHeader, StatusListTokenPayload>(),
                resolvedAt = null,
            )

            statusListToken.validate(
                verifyJwsObject = { KmmResult.success(SignatureVerifier.Success) },
                revocationListInfo = StatusListInfo(index = 0u, uri = issued.payload.subject),
                isInstantInThePast = { false },
            ).exceptionOrNull().toString().shouldContain("Invalid type header")
        }
    }
}
