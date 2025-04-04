package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TransactionData
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.QesAuthorization
import at.asitplus.rqes.collection_entries.RqesDocumentDigestEntry
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.*
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions.Query
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

@Suppress("DEPRECATION")
class RqesRequestOptionsTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var rqesVerifier: OpenId4VpVerifier
    lateinit var requestOptions: RqesRequestOptions

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
        rqesVerifier = OpenId4VpVerifier(
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
            val authnRequestUrl = rqesVerifier.createAuthnRequest(requestOptions, Query(walletUrl))
                .getOrThrow().url
            authnRequestUrl shouldContain "transaction_data"

            val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

            result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload.apply {
                transactionData.shouldNotBeNull().first() shouldBe requestOptions.transactionData!!.first()
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashesAlgorithm.shouldNotBeNull()
            }
        }

        "UC5-Specific Flow: KeyBindingJws contains transaction data" {
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
                transactionData.shouldNotBeNull().first() shouldBe requestOptions.transactionData!!.first()
                //TODO maybe introduce strict separation of the two flows
                transactionDataHashes.shouldNotBeNull()
                transactionDataHashesAlgorithm.shouldNotBeNull()
            }
        }
    }
})

private fun buildExtendedRequestOptions(): RqesRequestOptions =
    RqesRequestOptions(
        baseRequestOptions = OpenIdRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    EuPidScheme, SD_JWT, setOf(FAMILY_NAME, GIVEN_NAME)
                )
            ),
            transactionData = setOf(getTransactionData())
        )
    )

//TODO other transactionData
private fun getTransactionData(): TransactionData = QesAuthorization.create(
    documentDigest = listOf(getDocumentDigests()),
    signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
    credentialId = uuid4().toString(),
).getOrThrow()

@Suppress("DEPRECATION")
private fun getDocumentDigests(): RqesDocumentDigestEntry = RqesDocumentDigestEntry.create(
    label = uuid4().toString(),
    hash = uuid4().bytes,
    documentLocationUri = uuid4().toString(),
    documentLocationMethod = RqesDocumentDigestEntry.DocumentLocationMethod(
        documentAccessMode = RqesDocumentDigestEntry.DocumentLocationMethod.DocumentAccessMode.OAUTH2
    ),
    hashAlgorithmOID = Digest.entries.random().oid,
).getOrThrow()
