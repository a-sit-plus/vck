package at.asitplus.wallet.lib.agent

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllMandatoryClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.agent.QesApprovalTestData.approvalJson
import at.asitplus.wallet.lib.agent.QesApprovalTestData.encodeTransactionData
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

/**
 * Transaction data name the credential queries they apply to (OpenID4VP 1.0, 8.4): only those need holder binding, so
 * an SD-JWT VC without `cnf` can be presented for another query of the same request.
 */
val UnboundSdJwtTransactionDataTest by matrixSuite {

    fixture {
        runBlocking {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(keyMaterial = holderKeyMaterial)
            val boundCredential = issueAndStoreSdJwt(holder, holderKeyMaterial, issuer)
            // Suspending calls belong to the coroutine body, not to the initializers of the object
            val unbound = unboundCredential()
            object {
                val holder = holder
                val boundCredential = boundCredential
                val unboundCredential = unbound
            }
        }
    } - {

        test("an SD-JWT VC without cnf is presented without KB-JWT next to transaction data for another query") {
            val transactionData = encodeTransactionData(
                approvalJson(Digest.SHA256.oid.toString(), listOf(BOUND_QUERY_ID.string))
            )

            val presentations = it.holder.present(it.boundCredential, it.unboundCredential, transactionData)
                .getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
                .verifiablePresentations

            presentations.getValue(BOUND_QUERY_ID).single().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .sdJwt.keyBindingJws.shouldNotBeNull()
                .payload.transactionDataHashes.shouldNotBeNull()
            presentations.getValue(UNBOUND_QUERY_ID).single().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .sdJwt.keyBindingJws.shouldBeNull()
        }

        test("an SD-JWT VC without cnf can't be presented for a query that transaction data name") {
            val transactionData = encodeTransactionData(
                approvalJson(Digest.SHA256.oid.toString(), listOf(UNBOUND_QUERY_ID.string))
            )

            it.holder.present(it.boundCredential, it.unboundCredential, transactionData)
                .exceptionOrNull().shouldBeInstanceOf<PresentationException>()
                .message shouldBe "Transaction data require holder binding, which the credential does not have"
        }
    }
}

private suspend fun Holder.present(
    boundCredential: StoreEntry,
    unboundCredential: StoreEntry,
    transactionData: String,
) = createPresentation(
    request = PresentationRequestParameters(
        nonce = uuid4().toString(),
        audience = "https://verifier.example.org",
        transactionData = listOf(JsonPrimitive(transactionData)),
    ),
    credentialPresentation = CredentialPresentationRequest.DCQLRequest(dcqlQuery()).toCredentialPresentation(
        mapOf(
            BOUND_QUERY_ID to listOf(
                DCQLCredentialSubmissionOption(boundCredential, AllMandatoryClaimsMatchingResult)
            ),
            UNBOUND_QUERY_ID to listOf(
                DCQLCredentialSubmissionOption(unboundCredential, AllClaimsMatchingResult)
            ),
        )
    ),
)

private fun dcqlQuery() = Json.decodeFromString<DCQLQuery>(
    """{
        "credentials": [
            {
                "id": "${BOUND_QUERY_ID.string}", "format": "dc+sd-jwt",
                "meta": {"vct_values": ["${ConstantIndex.AtomicAttribute2023.sdJwtType}"]}
            },
            {
                "id": "${UNBOUND_QUERY_ID.string}", "format": "dc+sd-jwt",
                "meta": {"vct_values": ["$UNBOUND_VCT"]},
                "require_cryptographic_holder_binding": false
            }
        ]
    }""".trimIndent()
)

/** An SD-JWT VC without `cnf`, i.e. not holder-bound. */
private suspend fun unboundCredential(): StoreEntry.SdJwt {
    val salt = Random.nextBytes(16).encodeToString(Base64UrlStrict)
    val disclosure = """["$salt", "family_name", "Musterfrau"]""".encodeToByteArray().encodeToString(Base64UrlStrict)
    val jws = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
        JwsContentTypeConstants.SD_JWT,
        buildJsonObject {
            put("vct", UNBOUND_VCT)
            put("_sd", buildJsonArray { add(disclosure.hashDisclosure()) })
            put("_sd_alg", "sha-256")
        },
        JsonObject.serializer(),
    ).getOrThrow()
    return StoreEntry.SdJwt(
        vcSerialized = "${jws.jws}~$disclosure~",
        sdJwt = VerifiableCredentialSdJwt(verifiableCredentialType = UNBOUND_VCT),
        disclosures = mapOf(
            disclosure to SelectiveDisclosureItem(
                salt = salt.decodeToByteArray(Base64UrlStrict),
                claimName = "family_name",
                claimValue = JsonPrimitive("Musterfrau"),
            )
        ),
        schemeIdentifier = "unbound",
    )
}

private const val UNBOUND_VCT = "https://example.com/credentials/unbound"
private val BOUND_QUERY_ID = DCQLCredentialQueryIdentifier("bound-credential")
private val UNBOUND_QUERY_ID = DCQLCredentialQueryIdentifier("unbound-credential")
