package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry
import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry.DocumentLocationMethod
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toTransactionData
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.wallet.lib.openid.RequestOptionsCredential
import at.asitplus.wallet.lib.rqes.helper.DummyCredentialDataProvider
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class RqesRequestOptionsTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var verifierOid4Vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ).issueCredential(
                DummyCredentialDataProvider.getCredential(holderKeyMaterial.publicKey, EuPidScheme, SD_JWT)
                    .getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
        verifierOid4Vp = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri("https://example.com/rp/${uuid4()}"),
        )
    }

    "Authentication request contains transactionData" {
        verifierOid4Vp.createAuthnRequest(requestOptions = buildRequestOptions()).apply {
            val inputDescriptor = presentationDefinition.shouldNotBeNull().inputDescriptors.first()
            transactionData.shouldNotBeNull().first().toTransactionData().apply {
                transactionDataHashAlgorithms shouldNotBe null
                credentialIds!!.first() shouldBe inputDescriptor.id
            }
        }
    }
})

internal fun buildRequestOptions(
    responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
) = uuid4().toString().let { credentialId ->
    RequestOptions(
        responseMode = responseMode,
        responseUrl = if (responseMode == OpenIdConstants.ResponseMode.DirectPost)
            "https://example.com/rp/${uuid4()}"
        else null,
        credentials = setOf(
            RequestOptionsCredential(
                credentialScheme = EuPidScheme,
                representation = SD_JWT,
                requestedAttributes = setOf(FAMILY_NAME, GIVEN_NAME),
                id = credentialId
            )
        ),
        transactionData = listOf(
            buildTransactionData(setOf(credentialId)),
            buildTransactionData(setOf(credentialId))
        ),
    )
}

private fun buildTransactionData(ids: Set<String>): TransactionData = QesAuthorization.create(
    documentDigest = listOf(buildDocumentDigests()),
    signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
    credentialId = uuid4().toString(),
    credentialIds = ids,
    transactionDataHashAlgorithms = setOf(Digest.SHA256.oid.toString()),
).getOrThrow()

private fun buildDocumentDigests(): RqesDocumentDigestEntry = RqesDocumentDigestEntry.create(
    label = uuid4().toString(),
    hash = uuid4().bytes,
    documentLocationUri = uuid4().toString(),
    documentLocationMethod = DocumentLocationMethod(
        documentAccessMode = DocumentLocationMethod.DocumentAccessMode.OAUTH2
    ),
    hashAlgorithmOID = Digest.entries.random().oid,
).getOrThrow()
