package at.asitplus.wallet.lib.etsi

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe

val LoTEProfileUrlTest by matrixSuite {

    test("resolve the file name of every profile against a base URL") {
        LoteProfile.fetchUrls("https://example.test/lists") shouldContainExactly
                LoteProfile.entries.map { "https://example.test/lists/${it.fileName}" }
    }

    test("ignore a trailing slash in the base URL") {
        LoteProfile.PID.fetchUrl("https://example.test/lists/") shouldBe
                LoteProfile.PID.fetchUrl("https://example.test/lists")
    }

    test("serve the same lists on every stage") {
        LoTEStage.entries.forEach { stage ->
            stage.fetchUrls shouldContainExactly LoteProfile.entries.map { stage.fetchUrl(it) }
        }
    }

    test("fetch the lists of every passed stage") {
        LoteProfile.fetchUrls(LoTEStage.ACCEPTANCE, LoTEStage.DEVELOPMENT) shouldContainExactly
                LoTEStage.ACCEPTANCE.fetchUrls + LoTEStage.DEVELOPMENT.fetchUrls
    }

    test("keep the published URLs of the deployed stages") {
        LoTEStage.ACCEPTANCE.fetchUrl(LoteProfile.PID) shouldBe
                "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json"
        LoTEStage.DEVELOPMENT.fetchUrl(LoteProfile.WRPAC) shouldBe
                "https://development.trust.tech.ec.europa.eu/lists/eudiw/wrpac-providers.json"
    }
}
