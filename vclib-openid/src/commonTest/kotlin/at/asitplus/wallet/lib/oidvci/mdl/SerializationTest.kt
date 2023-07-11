package at.asitplus.wallet.lib.oidvci.mdl

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class SerializationTest : FunSpec({

    fun createClaimDisplayProperties() = ClaimDisplayProperties(
        name = "Given Name",
        locale = "de-AT",
    )

    fun createRequestedCredentialClaimSpecification() = RequestedCredentialClaimSpecification(
        valueType = "string",
        display = createClaimDisplayProperties(),
    )

    test("createAuthorizationRequest as GET") {
        val claimDisplayProperties = createClaimDisplayProperties()

        val serializedClaim = Json.encodeToString(claimDisplayProperties)

        serializedClaim.filter {
            !it.isWhitespace()
        } shouldBe "{ \"name\": \"Given Name\", \"locale\": \"de-AT\" }".filter {
            !it.isWhitespace()
        }
    }
})