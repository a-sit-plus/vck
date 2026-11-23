package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking

val AgentIsoMdocRevocationTest by matrixSuite {

    for (mode in IsoRevocationMode.entries) for (format in mode.formats) {
        "${mode.description} token as $format" - {
            fixture { runBlocking { createIsoMdocFixture(mode, format) } } - {
                "dcql: simple walk-through success" {
                    val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)

                    it.verifyPresentation(vp).assertPresentedClaims(expectDateOfBirth = true)
                }

                "dcql: revoked credential" {
                    val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)

                    it.revokeSingleStoredCredential() shouldBe true

                    val verifyPresentation = it.verifyPresentation(vp)
                    verifyPresentation.presentation.shouldBeNull()
                    verifyPresentation.observedStatus shouldBe TokenStatus.Invalid
                }
            }
        }
    }
}
