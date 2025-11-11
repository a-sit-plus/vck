package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

class VerifiableCredentialTest : FunSpec({

    test("convenience constructor uses provided clock for issuance and expiration") {
        val issuanceInstant = Instant.fromEpochMilliseconds(1_726_358_400_000)
        val lifetime: Duration = 15.minutes
        val clock = object : Clock {
            override fun now(): Instant = issuanceInstant
        }

        val status = Status(
            statusList = StatusListInfo(
                index = 0u,
                uri = UniformResourceIdentifier("https://example.com/status-list"),
            ),
        )

        val credential = VerifiableCredential(
            id = "urn:uuid:test",
            issuer = "did:example:issuer",
            lifetime = lifetime,
            credentialStatus = status,
            credentialSubject = TestCredentialSubject("did:example:holder"),
            credentialType = "ExampleCredential",
            clock = clock,
        )

        credential.issuanceDate shouldBe issuanceInstant
        credential.expirationDate shouldBe issuanceInstant + lifetime
    }
})

@Serializable
private data class TestCredentialSubject(
    @SerialName("id")
    override val id: String,
) : CredentialSubject()

