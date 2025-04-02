package at.asitplus.wallet.lib.rqes

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
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.*
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions.Query
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

@Suppress("DEPRECATION")
class RqesRequestOptionsTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    var requestOptions: RqesRequestOptions = buildRqesRequestOptions()
    var transactionDataReferenceHashes: Set<ByteArray> = getReferenceHashes(requestOptions.transactionData!!)

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
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

        requestOptions = buildRqesRequestOptions()
        transactionDataReferenceHashes = getReferenceHashes(requestOptions.transactionData!!)
    }

    "Rqes Request with EU PID credential" - {
        val walletUrl = "https://example.com/wallet/${uuid4()}"
        val clientId = "https://example.com/rp/${uuid4()}"
        val rqesVerifier = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )

        "Authentication request contains transactionData" - {
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions = requestOptions)
            val inputDescriptor = authnRequest.presentationDefinition!!.inputDescriptors.first()
            authnRequest.presentationDefinition.shouldNotBeNull()
            inputDescriptor.shouldBeInstanceOf<QesInputDescriptor>()

            "OID4VP" {
                authnRequest.transactionData shouldNotBe null
                with(authnRequest.transactionData!!.first()) {
                    shouldNotBeNull()
                    transactionDataHashAlgorithms shouldNotBe null
                    credentialIds!!.first() shouldBe inputDescriptor.id
                }
            }

            "UC5" {
                inputDescriptor.transactionData shouldNotBe null
                with(inputDescriptor.transactionData!!.first()) {
                    shouldNotBeNull()
                    credentialIds shouldBe null
                    transactionDataHashAlgorithms shouldBe null
                }
            }
        }

        "KB-JWT contains transaction data" - {
            "OID4VP" {
                //[AuthenticationRequestParameter] do not contain [transactionData] in [presentationDefinition]
                val rawRequest = rqesVerifier.createAuthnRequest(requestOptions)
                val newInputDescriptors = rawRequest.presentationDefinition!!.inputDescriptors.map {
                    (it as QesInputDescriptor).copy(transactionData = null)
                }
                val authnRequest =
                    rawRequest.copy(presentationDefinition = rawRequest.presentationDefinition!!.copy(inputDescriptors = newInputDescriptors))

                val authnRequestUrl = URLBuilder(walletUrl).apply {
                    authnRequest.encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString()

                authnRequestUrl shouldContain "transaction_data"

                val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

                with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                    transactionData.shouldBeNull()
                    transactionDataHashes.shouldNotBeNull()
                    transactionDataHashes!!.first().contentEquals(transactionDataReferenceHashes.first())
                    transactionDataHashesAlgorithm.shouldNotBeNull()
                }
            }

            "UC5" {
                //[AuthenticationRequestParameter] do not contain [transactionData] directly
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
                    transactionDataHashes.shouldBeNull()
                    transactionDataHashesAlgorithm.shouldBeNull()
                }
            }

            "Generic" {
                //[AuthenticationRequestParameter] contain both versions - in this case prefer OID4VP
                val authnRequestUrl = rqesVerifier.createAuthnRequest(requestOptions, Query(walletUrl)).getOrThrow().url

                val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = rqesVerifier.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()

                with(result.sdJwtSigned.keyBindingJws.shouldNotBeNull().payload) {
                    transactionData.shouldBeNull()
                    transactionDataHashes.shouldNotBeNull()
                    transactionDataHashes!!.first().contentEquals(transactionDataReferenceHashes.first())
                    transactionDataHashesAlgorithm.shouldNotBeNull()
                }
            }
        }
    }
})

fun getReferenceHashes(transactionData: Set<TransactionData>): Set<ByteArray> {
    val encoded = transactionData.map {
        vckJsonSerializer.encodeToString(Base64URLTransactionDataSerializer, it)
    }
    return encoded.map { vckJsonSerializer.decodeFromString<String>(it).decodeToByteArray(Base64UrlStrict).sha256() }
        .toSet()
}

private fun buildRqesRequestOptions(): RqesRequestOptions {
    val id = uuid4().toString()
    return RqesRequestOptions(
        baseRequestOptions = OpenIdRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    EuPidScheme, SD_JWT,
                    setOf(FAMILY_NAME, GIVEN_NAME),
                    id = id
                )
            ),
            transactionData = setOf(getTransactionData(setOf(id)))
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
