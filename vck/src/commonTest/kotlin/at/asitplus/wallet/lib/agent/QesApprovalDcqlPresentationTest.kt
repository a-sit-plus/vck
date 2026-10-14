package at.asitplus.wallet.lib.agent

import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllMandatoryClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.agent.QesApprovalTestData.approvalJson
import at.asitplus.wallet.lib.agent.QesApprovalTestData.encodeTransactionData
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive

val QesApprovalDcqlPresentationTest by matrixSuite {

    fixture {
        runBlocking {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(
                keyMaterial = holderKeyMaterial,
                mdocZkEngine = at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine(
                    at.asitplus.wallet.lib.zk.iso.IsoMdocZkBackendRegistry()
                ),
            )
            val sdJwtCredential = issueAndStoreSdJwt(holder, holderKeyMaterial, issuer)
            val isoCredential = issueAndStoreIsoMdoc(holder, holderKeyMaterial, issuer)
            object {
                val holder = holder
                val sdJwtCredential = sdJwtCredential
                val isoCredential = isoCredential
            }
        }
    } - {
        "QES approval query scoping" - { fixture ->
            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: referenced query only" }) test { format ->
                val raw = approvalJson(Digest.SHA256.oid.toString())
                val encoded = encodeTransactionData(raw)
                val presentations = fixture.holder.createMultiQueryPresentation(format, listOf(JsonPrimitive(encoded)))

                presentations.getValue(APPROVAL_QUERY_ID).single().qesApprovalDigest()
                    .shouldNotBeNull().contentEquals(format.digest(raw, encoded, Digest.SHA256)) shouldBe true
                presentations.getValue(IDENTITY_QUERY_ID).single().qesApprovalDigest().shouldBeNull()
            }

            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: distinct query approvals" }) test { format ->
                val approval = approvalJson(Digest.SHA256.oid.toString())
                val identity = approvalJson(Digest.SHA384.oid.toString(), listOf(IDENTITY_QUERY_ID.string))
                val approvalEncoded = encodeTransactionData(approval)
                val identityEncoded = encodeTransactionData(identity)
                val presentations = fixture.holder.createMultiQueryPresentation(
                    format,
                    listOf(JsonPrimitive(approvalEncoded), JsonPrimitive(identityEncoded)),
                )

                presentations.getValue(APPROVAL_QUERY_ID).single().qesApprovalDigest()
                    .shouldNotBeNull()
                    .contentEquals(format.digest(approval, approvalEncoded, Digest.SHA256)) shouldBe true
                presentations.getValue(IDENTITY_QUERY_ID).single().qesApprovalDigest()
                    .shouldNotBeNull()
                    .contentEquals(format.digest(identity, identityEncoded, Digest.SHA384)) shouldBe true
            }

            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: alternative query IDs authorize once" }) test { format ->
                val raw = approvalJson(
                    Digest.SHA256.oid.toString(),
                    listOf(IDENTITY_QUERY_ID.string, APPROVAL_QUERY_ID.string),
                )
                val encoded = encodeTransactionData(raw)
                val presentations = fixture.holder.createMultiQueryPresentation(format, listOf(JsonPrimitive(encoded)))
                val approvals = presentations.values.flatten().mapNotNull { it.qesApprovalDigest() }

                approvals shouldHaveSize 1
                approvals.single().contentEquals(format.digest(raw, encoded, Digest.SHA256)) shouldBe true
            }

            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: flexible approval uses alternative" }) test { format ->
                val flexible = approvalJson(
                    Digest.SHA256.oid.toString(),
                    listOf(APPROVAL_QUERY_ID.string, IDENTITY_QUERY_ID.string),
                )
                val fixed = approvalJson(Digest.SHA384.oid.toString())
                val flexibleEncoded = encodeTransactionData(flexible)
                val fixedEncoded = encodeTransactionData(fixed)
                val presentations = fixture.holder.createMultiQueryPresentation(
                    format,
                    listOf(JsonPrimitive(flexibleEncoded), JsonPrimitive(fixedEncoded)),
                )

                presentations.getValue(APPROVAL_QUERY_ID).single().qesApprovalDigest()
                    .shouldNotBeNull().contentEquals(format.digest(fixed, fixedEncoded, Digest.SHA384)) shouldBe true
                presentations.getValue(IDENTITY_QUERY_ID).single().qesApprovalDigest()
                    .shouldNotBeNull()
                    .contentEquals(format.digest(flexible, flexibleEncoded, Digest.SHA256)) shouldBe true
            }

            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: single approval across submissions" }) test { format ->
                val raw = approvalJson(Digest.SHA256.oid.toString())
                val encoded = encodeTransactionData(raw)
                val query = format.query(multiple = true)
                val credential: StoreEntry = when (format) {
                    QesCredentialFormat.SdJwt -> fixture.sdJwtCredential
                    QesCredentialFormat.IsoMdoc -> fixture.isoCredential
                }
                val submission = DCQLCredentialSubmissionOption<StoreEntry>(
                    credential = credential,
                    matchingResult = AllMandatoryClaimsMatchingResult,
                )
                val result = fixture.holder.createPresentation(
                    request = presentationRequest(listOf(JsonPrimitive(encoded))),
                    credentialPresentation = CredentialPresentationRequest.DCQLRequest(query)
                        .toCredentialPresentation(mapOf(APPROVAL_QUERY_ID to listOf(submission, submission))),
                ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
                val presentations = result.verifiablePresentations.getValue(APPROVAL_QUERY_ID)
                presentations shouldHaveSize 2
                val approvals = presentations.mapNotNull { it.qesApprovalDigest() }

                approvals shouldHaveSize 1
                approvals.single().contentEquals(format.digest(raw, encoded, Digest.SHA256)) shouldBe true
            }

            QesCredentialFormat.entries.flatMap { format ->
                listOf(null, emptyList(), listOf("unknown-query")).map { ids -> format to ids }
            }.asData(
                nameFn = { (format, ids) -> "${format.name}: rejects invalid credential_ids $ids" },
            ) test { (format, ids) ->
                val raw = approvalJson(Digest.SHA256.oid.toString(), ids)
                val encoded = encodeTransactionData(raw)
                shouldThrow<PresentationException> {
                    fixture.holder.createMultiQueryPresentation(format, listOf(JsonPrimitive(encoded)))
                }
            }

            QesCredentialFormat.entries.asData(nameFn = { "${it.name}: rejects approvals targeting same submission" }) test { format ->
                val first = encodeTransactionData(approvalJson(Digest.SHA256.oid.toString()))
                val second = encodeTransactionData(approvalJson(Digest.SHA384.oid.toString()))
                shouldThrow<PresentationException> {
                    fixture.holder.createMultiQueryPresentation(
                        format,
                        listOf(JsonPrimitive(first), JsonPrimitive(second)),
                    )
                }.message shouldBe "Only one qesApprovalRequest may be presented per credential submission"
            }
        }
    }
}

private enum class QesCredentialFormat(
    val queryFormat: String,
    val queryMeta: String,
    val identityClaimPath: String,
) {
    SdJwt(
        queryFormat = "dc+sd-jwt",
        queryMeta = """{"vct_values":["${ConstantIndex.AtomicAttribute2023.sdJwtType}"]}""",
        identityClaimPath = """["${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]""",
    ),
    IsoMdoc(
        queryFormat = "mso_mdoc",
        queryMeta = """{"doctype_value":"${ConstantIndex.AtomicAttribute2023.isoDocType}"}""",
        identityClaimPath = """["${ConstantIndex.AtomicAttribute2023.isoNamespace}","${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]""",
    );

    fun query(multiple: Boolean = false) = Json.decodeFromString<DCQLQuery>(
        """{
            "credentials": [{
                "id": "${APPROVAL_QUERY_ID.string}", "format": "$queryFormat", "multiple": $multiple,
                "meta": $queryMeta
            }]
        }""".trimIndent()
    )

    fun dcqlQuery() = Json.decodeFromString<DCQLQuery>(
        """{
            "credentials": [
                {
                    "id": "${APPROVAL_QUERY_ID.string}", "format": "$queryFormat", "meta": $queryMeta
                },
                {
                    "id": "${IDENTITY_QUERY_ID.string}", "format": "$queryFormat", "meta": $queryMeta,
                    "claims": [{ "path": $identityClaimPath }]
                }
            ]
        }""".trimIndent()
    )

    fun digest(raw: String, encoded: String, algorithm: Digest) =
        algorithm.digest((if (this == SdJwt) encoded else raw).encodeToByteArray())
}

private suspend fun Holder.createMultiQueryPresentation(
    format: QesCredentialFormat,
    transactionData: List<JsonPrimitive>,
) = createDefaultPresentation(
    request = presentationRequest(transactionData),
    credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(format.dcqlQuery()),
).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
    .verifiablePresentations.also {
        it.keys shouldBe setOf(APPROVAL_QUERY_ID, IDENTITY_QUERY_ID)
    }

private fun presentationRequest(transactionData: List<JsonPrimitive>) = PresentationRequestParameters(
    nonce = uuid4().toString(),
    audience = "https://verifier.example.org",
    transactionData = transactionData,
    calcIsoSessionTranscript = {
        SessionTranscript.forQr(deviceEngagementBytes = byteArrayOf(), eReaderKeyBytes = byteArrayOf())
    },
)

private val APPROVAL_QUERY_ID = DCQLCredentialQueryIdentifier("approval-credential")
private val IDENTITY_QUERY_ID = DCQLCredentialQueryIdentifier("identity-credential")
