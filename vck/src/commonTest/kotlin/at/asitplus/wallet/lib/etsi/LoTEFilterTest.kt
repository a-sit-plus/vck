package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.testballoon.matrix.matrixSuite
import com.goncalossilva.resources.Resource
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json

/**
 * Filters the lists of trusted entities from `etsi-data-classes/src/commonTest/resources/lote`, which
 * `vck/build.gradle.kts` adds to the test resources of this module.
 */
val LoTEFilterTest by matrixSuite {

    data class TestData(
        val resource: String,
        val schemeIdentifier: String? = null,
        val fixedProfile: LoteProfile? = null
    )

    testSuite("filter lote by type identifier") {
        mapOf(
            "pidProviders" to TestData(
                resource = "lote/pid-providers-seq4.json",
                schemeIdentifier = "urn:eudi:pid:de:1"
            ),
            "walletProviders" to TestData(
                resource = "lote/wallet-providers-seq2.json",
                fixedProfile = LoteProfile.WALLET
            ),
            "wrpacProviders" to TestData(
                resource = "lote/wrpac-providers-seq2.json",
                fixedProfile = LoteProfile.WRPAC
            ),
            "mdlProviders" to TestData(
                resource = "lote/mdl-providers-seq2.json",
                schemeIdentifier = "org.iso.18013.5.1.mDL"
            ),
        ).asData() test { entry ->
            val data = entry.second
            val lote = Json.decodeFromString<ListOfTrustedEntities>(Resource(data.resource).readText())
            val expectedProfile =
                checkNotNull(data.fixedProfile ?: LoteProfile.fromSchemeIdentifier(data.schemeIdentifier))
            val trustedCerts = LoTEFilterService().extractIssuanceCertificates(lote, expectedProfile)

            trustedCerts.size shouldNotBe 0
        }
    }
}
