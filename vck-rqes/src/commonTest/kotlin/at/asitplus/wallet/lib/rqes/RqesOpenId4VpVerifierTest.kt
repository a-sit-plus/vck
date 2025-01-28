package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.Method
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.RqesDocumentDigestEntry
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsCredential
import at.asitplus.wallet.lib.rqes.helper.Oid4VpRqesParameters
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*


private val requestedClaims = setOf(
    EuPidScheme.SdJwtAttributes.FAMILY_NAME,
    EuPidScheme.SdJwtAttributes.GIVEN_NAME,
)

private val defaultRequestOption = RequestOptions(
    credentials = setOf(
        RequestOptionsCredential(EuPidScheme, SD_JWT, requestedClaims)
    )
)

class DummyRequestOptionsService {
    fun getRequestOptions(): RqesOpenId4VpVerifier.ExtendedRequestOptions =
        RqesOpenId4VpVerifier.ExtendedRequestOptions(
            baseRequestOptions = defaultRequestOption, rqesParameters = Oid4VpRqesParameters(
                transactionData = setOf(getTransactionData())
            )
        )

    //TODO other transactionData
    private fun getTransactionData(): TransactionData = TransactionData.QesAuthorization.create(
        documentDigest = listOf(getDocumentDigests()),
        signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        credentialId = uuid4().toString(),
    ).getOrThrow()

    private fun getDocumentDigests(): RqesDocumentDigestEntry = RqesDocumentDigestEntry.create(
        label = uuid4().toString(),
        hash = uuid4().bytes,
        documentLocationUri = uuid4().toString(),
        documentLocationMethod = RqesDocumentDigestEntry.DocumentLocationMethod(
            method = Method.Oauth2
        ),
        hashAlgorithmOID = Digest.entries.random().oid,
    ).getOrThrow()
}

val dummyRequestOptionsService = DummyRequestOptionsService()

/**
 * Tests copied from [OpenId4VpProtocolTest] then extended
 */
class RqesOpenId4VpVerifierTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var rqesOpenId4VpVerifier: RqesOpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        rqesOpenId4VpVerifier = RqesOpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
    }

    "Rqes Request with EU PID credential" {

        val requestOptions = dummyRequestOptionsService.getRequestOptions()

        val authnRequest = rqesOpenId4VpVerifier.createAuthnRequest(
            requestOptions = requestOptions,
        )
        authnRequest.transactionData shouldNotBe null
        authnRequest.presentationDefinition shouldNotBe null
        (authnRequest.presentationDefinition!!.inputDescriptors.first() is QesInputDescriptor) shouldBe true
        (authnRequest.presentationDefinition!!.inputDescriptors.first() as QesInputDescriptor).transactionData shouldNotBe null

        val authnRequestUrl = rqesOpenId4VpVerifier.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = requestOptions
        )

        authnRequestUrl shouldContain "transaction_data"

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = rqesOpenId4VpVerifier.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        result.verifiableCredentialSdJwt.shouldNotBeNull()
        requestedClaims.forEach {
            it.shouldBeIn(result.reconstructed.keys)
            result.reconstructed[it].shouldNotBeNull()
        }
    }
})
