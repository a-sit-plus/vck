package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry
import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry.DocumentLocationMethod
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements.FAMILY_NAME
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements.GIVEN_NAME
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.toTransactionData
import io.ktor.http.Url
import at.asitplus.openid.decodeFromQuery
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.CreationOptions
import at.asitplus.wallet.lib.openid.CredentialPresentationRequestBuilder
import at.asitplus.wallet.lib.openid.OpenId4VpRequestOptions
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val RqesRequestOptionsTest by matrixSuite {

    fixture {
        object {
            val verifierOid4Vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.RedirectUri("https://example.com/rp/${uuid4()}"),
            )
        }
    } - {

        test("Authentication request contains transactionData") {
            val requestOptions = buildRequestOptions(transactionDataHashAlgorithms = setOf(SdJwtConstants.SHA_256))
            it.verifierOid4Vp.createAuthnRequest(requestOptions, CreationOptions.Query("https://example.com"))
                .getOrThrow().url.let { Url(it) }.decodeFromQuery<AuthenticationRequestParameters>().apply {
                    val dcqlId = dcqlQuery.shouldNotBeNull().credentials.first().id
                    transactionData.shouldNotBeNull().first().toTransactionData().apply {
                        transactionDataHashAlgorithms shouldNotBe null
                        credentialIds.first() shouldBe dcqlId.string
                    }
                }
        }
    }
}

internal suspend fun buildRequestOptions(
    responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
    transactionDataHashAlgorithms: Set<String>?,
): OpenId4VpRequestOptions = uuid4().toString().let { credentialId ->
    return OpenId4VpRequestOptions(
        responseMode = responseMode,
        responseUrl = if (responseMode == OpenIdConstants.ResponseMode.DirectPost)
            "https://example.com/rp/${uuid4()}"
        else null,
        presentationRequest = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT),
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer(FAMILY_NAME), DCQLClaimsPathPointer(GIVEN_NAME)),
                id = credentialId
            )
        ).toDCQLRequest(),
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
