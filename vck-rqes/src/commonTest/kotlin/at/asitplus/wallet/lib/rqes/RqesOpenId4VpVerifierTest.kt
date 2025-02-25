package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.RqesDocumentDigestEntry
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthnResponseResult
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions.Query
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsCredential
import at.asitplus.wallet.lib.rqes.helper.OpenIdRqesParameters
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.encodeToString

@Suppress("DEPRECATION")
class RqesOpenId4VpVerifierTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var rqesVerifier: RqesOpenId4VpVerifier
    lateinit var requestOptions: RqesOpenId4VpVerifier.ExtendedRequestOptions

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
        rqesVerifier = RqesOpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
        requestOptions = buildExtendedRequestOptions()
    }

    "Rqes Request with EU PID credential" - {

        "Authentication request contains transaction data" {
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions = requestOptions)

            authnRequest.transactionData shouldNotBe null
            authnRequest.presentationDefinition.shouldNotBeNull()
            authnRequest.presentationDefinition!!.inputDescriptors.first()
                .shouldBeInstanceOf<QesInputDescriptor>()
                .transactionData.shouldNotBeNull()
        }

        "KB-JWT contains transaction data" {
            val transactionDataEncoded =
                vckJsonSerializer.encodeToString(requestOptions.rqesParameters.transactionData.first())
                    .encodeToByteArray()

            val authnRequestUrl = rqesVerifier.createAuthnRequest(requestOptions, Query(walletUrl))
                .getOrThrow().url
            authnRequestUrl shouldContain "transaction_data"

            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

            result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.apply {
                transactionData.shouldNotBeNull().first() shouldBe transactionDataEncoded
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashesAlgorithm.shouldNotBeNull()
            }
        }

        "UC5-Specific Flow: KeyBindingJws contains transaction data" {
            val transactionDataEncoded =
                vckJsonSerializer.encodeToString(requestOptions.rqesParameters.transactionData.first())
                    .encodeToByteArray()

            //Do not use [AuthenticationRequestParameters.transactionData] introduced in OpenID4VP
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions).copy(transactionData = null)

            val authnRequestUrl = URLBuilder(walletUrl).apply {
                authnRequest.encodeToParameters()
                    .forEach { parameters.append(it.key, it.value) }
            }.buildString()

            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

            result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.apply {
                transactionData.shouldNotBeNull().first() shouldBe transactionDataEncoded
                //TODO maybe introduce strict separation of the two flows
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashesAlgorithm.shouldNotBeNull()
            }
        }
    }
})

private fun buildExtendedRequestOptions(): RqesOpenId4VpVerifier.ExtendedRequestOptions =
    RqesOpenId4VpVerifier.ExtendedRequestOptions(
        baseRequestOptions = OpenIdRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    EuPidScheme, SD_JWT, setOf(FAMILY_NAME, GIVEN_NAME)
                )
            )
        ),
        rqesParameters = OpenIdRqesParameters(
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
        documentAccessMode = RqesDocumentDigestEntry.DocumentLocationMethod.DocumentAccessMode.OAUTH2
    ),
    hashAlgorithmOID = Digest.entries.random().oid,
).getOrThrow()
