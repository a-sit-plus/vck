package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpErrorResponseTest : FreeSpec({
    lateinit var clientId: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )
    }

    "Basic error response test" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = null
            )
        )
        authnRequest shouldNotBe null

        val response = holderOid4vp.createAuthnResponse(vckJsonSerializer.encodeToString(authnRequest))
        response.getOrNull().shouldBeInstanceOf<AuthenticationResponseResult.Post>().params.shouldContain(
            "error_description",
            "invalid_request: response_url is null"
        )
    }
})