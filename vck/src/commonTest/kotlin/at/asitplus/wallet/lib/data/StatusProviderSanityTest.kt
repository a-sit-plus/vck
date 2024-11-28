package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.CwtStatusListStatusMechanismSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.JwtStatusListStatusMechanismSpecification
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData

class StatusProviderSanityTest : FreeSpec({
    "jwt and cwt status mechanism key equivalence" - {
        withData(
            mapOf(
                "statusList" to mapOf(
                    "Json" to JwtStatusListStatusMechanismSpecification.NAME,
                    "Cbor" to CwtStatusListStatusMechanismSpecification.NAME,
                ),
            )
        ) { serialLabels ->
            val memberName = testCase.name.testName
            if (serialLabels.values.distinct().size != 1) {
                throw IllegalStateException("Member `$memberName` has different serial names between the following formats: [${
                    serialLabels.keys.joinToString(
                        ", "
                    ) { it }
                }]")
            }
        }
    }
})