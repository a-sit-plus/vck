package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc7519.jwt.headers.JwtTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc9596.cose.headers.CoseTypeHeaderParameterSpecification
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData

class StatusListTokenHeaderSanityTest : FreeSpec({
    "jwt and cwt key equivalences" - {
        withData(
            mapOf(
                "typ" to mapOf(
                    "Json" to JwtTypeHeaderParameterSpecification.NAME,
                    "Cbor" to CoseTypeHeaderParameterSpecification.NAME,
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