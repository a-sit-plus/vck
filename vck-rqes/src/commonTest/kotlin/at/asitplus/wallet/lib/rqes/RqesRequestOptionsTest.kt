package at.asitplus.wallet.lib.rqes

import at.asitplus.iso.sha256
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TransactionData
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.QesAuthorization
import at.asitplus.rqes.collection_entries.RqesDocumentDigestEntry
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.toTransactionData
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsCredential
import at.asitplus.wallet.lib.rqes.helper.DummyCredentialDataProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

@Suppress("DEPRECATION")
class RqesRequestOptionsTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder

    beforeContainer {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(identifier = "https://issuer.example.com/").issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
    }

    "Rqes Request with EU PID credential" - {
        val clientId = "https://example.com/rp/${uuid4()}"
        val rqesVerifier = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )

        "Authentication request contains transactionData" - {
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions = buildRqesRequestOptions(null))
            val inputDescriptor = authnRequest.presentationDefinition!!.inputDescriptors.first()
            val serialized = vckJsonSerializer.encodeToString(inputDescriptor)
            authnRequest.presentationDefinition.shouldNotBeNull()
            inputDescriptor.shouldBeInstanceOf<QesInputDescriptor>()
            serialized.shouldNotContain(QesInputDescriptor::class.simpleName!!)


            "OID4VP" {
                authnRequest.transactionData shouldNotBe null
                with(authnRequest.transactionData!!.first().toTransactionData()) {
                    shouldNotBeNull()
                    transactionDataHashAlgorithms shouldNotBe null
                    credentialIds!!.first() shouldBe inputDescriptor.id
                }
            }

            "UC5" {
                inputDescriptor.transactionData shouldNotBe null
                with(inputDescriptor.transactionData!!.first().toTransactionData()) {
                    shouldNotBeNull()
                    credentialIds shouldBe null
                    transactionDataHashAlgorithms shouldBe null
                }
            }
        }

    }
})

internal fun List<TransactionData>.getReferenceHashes(): List<ByteArray> =
    this.map { it.toBase64UrlJsonString().content.decodeToByteArray(Base64UrlStrict).sha256() }

internal fun buildRqesRequestOptions(flow: PresentationRequestParameters.Flow?, responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment): RqesRequestOptions {
    val id = uuid4().toString()
    return RqesRequestOptions(
        baseRequestOptions = OpenIdRequestOptions(
            responseMode = responseMode,
            responseUrl = if (responseMode == OpenIdConstants.ResponseMode.DirectPost) "https://example.com/rp/${uuid4()}" else null,
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = EuPidScheme,
                    representation = SD_JWT,
                    requestedAttributes = setOf(FAMILY_NAME, GIVEN_NAME),
                    id = id
                )
            ),
            transactionData = listOf(getTransactionData(setOf(id)), getTransactionData(setOf(id))),
            rqesFlow = flow
        )
    )
}

//TODO other transactionData
private fun getTransactionData(ids: Set<String>): TransactionData = QesAuthorization.create(
    documentDigest = listOf(getDocumentDigests()),
    signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
    credentialId = uuid4().toString(),
    credentialIds = ids,
    transactionDataHashAlgorithms = setOf(Digest.SHA256.oid.toString()),
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
