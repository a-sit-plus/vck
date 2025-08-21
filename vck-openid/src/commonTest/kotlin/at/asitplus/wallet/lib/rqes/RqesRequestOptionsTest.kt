package io.kotest.provided.at.asitplus.wallet.lib.rqes

import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.iso.sha256
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.data.toTransactionData
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsCredential
import io.kotest.provided.at.asitplus.wallet.lib.rqes.helper.DummyCredentialDataProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

class RqesRequestOptionsTest : FreeSpec({

    lateinit var holderKeyMaterial: SignKeyMaterial
    lateinit var holderAgent: Holder

    beforeContainer {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(identifier = "https://issuer.example.com/".toUri())
                .issueCredential(
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
            val authnRequest = rqesVerifier.createAuthnRequest(requestOptions = buildRequestOptions())
            val inputDescriptor = authnRequest.presentationDefinition!!.inputDescriptors.first()
            authnRequest.presentationDefinition.shouldNotBeNull()
            authnRequest.transactionData.shouldNotBeNull()
            with(authnRequest.transactionData!!.first().toTransactionData()) {
                shouldNotBeNull()
                transactionDataHashAlgorithms shouldNotBe null
                credentialIds!!.first() shouldBe inputDescriptor.id
            }
        }

    }
})

internal fun List<TransactionData>.getReferenceHashes(): List<ByteArray> =
    this.map { it.toBase64UrlJsonString().content.decodeToByteArray(Base64UrlStrict).sha256() }

internal fun buildRequestOptions(
    responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
): RequestOptions {
    val id = uuid4().toString()
    return RequestOptions(
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
    )
}

private fun getTransactionData(ids: Set<String>): TransactionData = QesAuthorization.create(
    documentDigest = listOf(getDocumentDigests()),
    signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
    credentialId = uuid4().toString(),
    credentialIds = ids,
    transactionDataHashAlgorithms = setOf(Digest.SHA256.oid.toString()),
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
