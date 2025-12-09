package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry
import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry.DocumentLocationMethod
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.FAMILY_NAME
import at.asitplus.wallet.eupid.EuPidScheme.SdJwtAttributes.GIVEN_NAME
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.toTransactionData
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.OpenId4VpRequestOptions
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val RqesRequestOptionsTest by testSuite {

    withFixtureGenerator {
        object {
            val verifierOid4Vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri("https://example.com/rp/${uuid4()}"),
            )
        }
    } - {

        test("Authentication request contains transactionData") {
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = setOf(SdJwtConstants.SHA_256))
            it.verifierOid4Vp.createAuthnRequest(requestOptions = requestOptions).apply {
                val inputDescriptor = presentationDefinition.shouldNotBeNull().inputDescriptors.first()
                transactionData.shouldNotBeNull().first().toTransactionData().apply {
                    transactionDataHashAlgorithms shouldNotBe null
                    credentialIds.first() shouldBe inputDescriptor.id
                }
            }
        }
    }
}

internal fun buildRequestOptions(
    responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
    transactionDataHashAlgorithms: Set<String>?,
): OpenId4VpRequestOptions = uuid4().toString().let { credentialId ->
    return OpenId4VpRequestOptions(
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
            getTransactionData(setOf(credentialId), transactionDataHashAlgorithms),
            getTransactionData(setOf(credentialId), transactionDataHashAlgorithms)
        ),
    )
}

private fun getTransactionData(ids: Set<String>, transactionDataHashAlgorithms: Set<String>?): TransactionData =
    QesAuthorization.create(
        documentDigest = listOf(buildDocumentDigests()),
        signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        credentialId = uuid4().toString(),
        credentialIds = ids,
        transactionDataHashAlgorithms = transactionDataHashAlgorithms,
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
