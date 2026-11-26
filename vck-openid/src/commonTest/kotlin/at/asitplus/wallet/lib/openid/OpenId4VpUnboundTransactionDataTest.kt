package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.decodeFromQuery
import at.asitplus.openid.formUrlEncode
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.toBase64UrlJsonString
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

/**
 * Transaction data name the credential queries they apply to, and need holder binding (OpenID4VP 1.0, IETF SD-JWT VC,
 * "Transaction Data"): the presentation for a query without holder binding is an SD-JWT VC without cnf and without
 * KB-JWT, and the verifier doesn't expect transaction data in it. VC-K's own requests don't mix such queries, but a
 * request created elsewhere may.
 */
val OpenId4VpUnboundTransactionDataTest by matrixSuite {

    "an SD-JWT VC without cnf for a query without holder binding is accepted next to transaction data for another query" {
        val holderKey = EphemeralKeyWithoutCert()
        val store = InMemorySubjectCredentialStore()
        val holder = HolderAgent(holderKey, subjectCredentialStore = store)
        issueAndStoreSdJwt(holder, holderKey)
        store.storeCredential(unboundCredential()).getOrThrow()
        val holderOid4vp = OpenId4VpHolder(holder = holder, randomSource = RandomSource.Default)

        val requestStore = at.asitplus.wallet.lib.utils.DefaultMapStore<String, AuthenticationRequestParameters>()
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.RedirectUri("https://example.com/rp/${uuid4()}"),
            stateToAuthnRequestStore = requestStore,
            presentationPolicy = testPresentationPolicy,
        )
        val created = verifierOid4vp.createAuthnRequest(
            requestOptions = OpenId4VpRequestOptions(
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = "https://example.com/rp/${uuid4()}",
                presentationRequest = CredentialPresentationRequest.DCQLRequest(dcqlQuery()),
            ),
            creationOptions = CreationOptions.Query("https://example.com/wallet/${uuid4()}"),
        ).getOrThrow().url
        val request = Url(created).decodeFromQuery<AuthenticationRequestParameters>().copy(
            transactionData = listOf(
                QCertCreationAcceptance(
                    credentialIds = setOf(BOUND_QUERY_ID.string),
                    qcTermsConditionsUri = uuid4().toString(),
                    qcHash = uuid4().bytes,
                    qcHashAlgorithmOid = Digest.SHA256.oid,
                ).toBase64UrlJsonString()
            )
        )
        // The verifier expects the transaction data of the request the wallet answers
        requestStore.put(request.state.shouldNotBeNull(), request)

        val response = holderOid4vp.createAuthorizationResponse(joseCompliantSerializer.encodeToString(request))
            .getOrThrow().shouldBeInstanceOf<AuthenticationResponseResult.Post>()

        val presentations = verifierOid4vp.validateAuthnResponse(response.params.formUrlEncode()).getOrThrow()
            .acceptedPresentations()
        presentations.getValue(BOUND_QUERY_ID).shouldBeSingleton().first()
            .shouldBeInstanceOf<ValidatedPresentation.SdJwt>().keyBinding.shouldNotBeNull()
        presentations.getValue(UNBOUND_QUERY_ID).shouldBeSingleton().first()
            .shouldBeInstanceOf<ValidatedPresentation.SdJwt>().keyBinding.shouldBeNull()
        presentations.size shouldBe 2
    }
}

private val BOUND_QUERY_ID = DCQLCredentialQueryIdentifier("bound-credential")
private val UNBOUND_QUERY_ID = DCQLCredentialQueryIdentifier("unbound-credential")
private const val UNBOUND_VCT = "https://example.com/credentials/unbound"

private fun dcqlQuery() = Json.decodeFromString<DCQLQuery>(
    """{
        "credentials": [
            {
                "id": "${BOUND_QUERY_ID.string}", "format": "dc+sd-jwt",
                "meta": {"vct_values": ["AtomicAttribute2023"]}
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
    val jws = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())(
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
