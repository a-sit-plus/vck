package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.time.Clock

val StatusListCwtPublicationTest by matrixSuite {
    "published status list CWT has COSE Sign1 tag 18" {
        val cwt = StatusListCwt(StatusListAgent().issueStatusListCwt(), Clock.System.now())
        val bytes = cwt.encodeForPublication()

        bytes[0].toInt() and 0xff shouldBe 0xd2
        bytes[1].toInt() and 0xff shouldBe 0x84

        val parsed = CoseSigned.deserialize(ByteArraySerializer(), bytes.drop(1).toByteArray()).getOrThrow()
        parsed.protectedHeader.type shouldBe MediaTypes.Application.STATUSLIST_CWT
        VerifyCoseSignature<ByteArray>()(parsed, byteArrayOf(), null).isSuccess shouldBe true
        coseCompliantSerializer.decodeFromByteArray<StatusListTokenPayload>(parsed.payload!!)
            .subject shouldBe cwt.parsedPayload.getOrThrow().subject
    }
}
