package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

private val compatibilityStatusListInfo = StatusListInfo(
    index = 7U,
    uri = UniformResourceIdentifier("https://example.com/statuslist.cwt"),
)

private fun MobileSecurityObject.statusAsIn701(): RevocationListInfo? = status

private fun VerifiableCredential.statusAsIn701(): RevocationListInfo? = credentialStatus

private fun VerifiableCredentialSdJwt.statusAsIn701(): RevocationListInfo? = statusElement

private fun RevocationListInfo.typeAsIn701(): String = when (this) {
    is StatusListInfo -> "status_list"
    is IdentifierListInfo -> "identifier_list"
}

val TokenStatusBackwardCompatibilityTest by matrixSuite {
    "7.0.1 credential constructors still accept a single status mechanism" {
        VerifiableCredential(
            id = "urn:example:credential",
            type = listOf("VerifiableCredential"),
            issuer = "https://example.com/issuer",
            issuanceDate = Instant.fromEpochSeconds(0),
            expirationDate = null,
            credentialStatus = compatibilityStatusListInfo,
            credentialSubject = JsonObject(emptyMap()),
        ).statusAsIn701() shouldBe compatibilityStatusListInfo

        VerifiableCredentialSdJwt(
            verifiableCredentialType = "https://example.com/credential",
            statusElement = compatibilityStatusListInfo,
        ).statusAsIn701() shouldBe compatibilityStatusListInfo

        compatibilityStatusListInfo.typeAsIn701() shouldBe "status_list"
    }

    "7.0.1 status serializer keeps singleton behavior" {
        val encoded = coseCompliantSerializer.encodeToByteArray(
            RevocationListInfo.StatusSurrogateSerializer,
            compatibilityStatusListInfo,
        )

        coseCompliantSerializer.decodeFromByteArray(
            RevocationListInfo.StatusSurrogateSerializer,
            encoded,
        ) shouldBe compatibilityStatusListInfo
    }
}
