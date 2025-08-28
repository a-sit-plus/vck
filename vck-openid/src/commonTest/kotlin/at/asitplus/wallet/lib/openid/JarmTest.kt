package at.asitplus.wallet.lib.openid

import at.asitplus.openid.*
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class JarmTest : FreeSpec({
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

        holderAgent.storeCredential(
            IssuerAgent(identifier = "https://issuer.example.com/".toUri()).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, AtomicAttribute2023, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        holderAgent.storeCredential(
            IssuerAgent(identifier = "https://issuer.example.com/".toUri()).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )
    }

    /**
     * Incorrect behaviour arises when the [RelyingPartyMetadata.jsonWebKeySet] cannot be
     * retrieved and [RelyingPartyMetadata.authorizationSignedResponseAlgString] is not set.
     */
    "DirectPostJwt must either be signed or encrypted" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, setOf(AtomicAttribute2023.CLAIM_GIVEN_NAME))
                ),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/${uuid4()}"
            )
        )
        authnRequest shouldNotBe null

        val invalidReq = authnRequest.copy(
            clientMetadata = authnRequest.clientMetadata?.copy(
                jsonWebKeySet = null,
                jsonWebKeySetUrl = "https://example.com/rp/${uuid4()}",
                authorizationSignedResponseAlgString = null
            )
        )

        val response = holderOid4vp.createAuthnResponse(vckJsonSerializer.encodeToString(invalidReq))
        response.exceptionOrNull() shouldNotBe null
        response.exceptionOrNull().shouldBeInstanceOf<OAuth2Exception.InvalidRequest>()
    }
})