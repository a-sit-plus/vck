package at.asitplus.wallet.lib.agent

import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.DocRequestInfo.Companion.SD_JWT_NAMESPACE
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.IsoSdJwtKeyBinding
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.sessionTranscriptBytes
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

private val transcript = SessionTranscript.Qr(Random.nextBytes(16), Random.nextBytes(16))

private val mapping = mapOf(
    "given_name" to DCQLClaimsPathPointer("given_name"),
    "postal_code" to DCQLClaimsPathPointer("address", "postal_code"),
    "locality" to DCQLClaimsPathPointer("address", "locality"),
    "missing" to DCQLClaimsPathPointer("address", "missing"),
    "nationalities" to DCQLClaimsPathPointer(NameSegment("nationalities"), NullSegment),
    "first_nationality" to DCQLClaimsPathPointer(NameSegment("nationalities"), IndexSegment(0U)),
)

private fun sdJwtDocRequest(
    vararg elements: String,
    docType: String = AtomicAttribute2023.sdJwtType,
    namespace: String = SD_JWT_NAMESPACE,
    alternatives: List<AlternativeDataElementsSet>? = null,
    readerAuth: CoseSigned<ByteArray>? = null,
) = DocRequest(
    itemsRequest = ByteStringWrapper(
        ItemsRequest(
            docType = docType,
            namespaces = mapOf(namespace to ItemsRequestList(elements.map { SingleItemsRequest(it, false) })),
            requestInfo = DocRequestInfo(
                docFormat = DocRequestInfo.DOC_FORMAT_SD_JWT,
                dataElementIdentifierMapping = mapping,
                alternativeDataElements = alternatives,
            ),
        )
    ),
    readerAuth = readerAuth,
)

private fun mdocDocRequest() = DocRequest(
    ByteStringWrapper(
        ItemsRequest(
            docType = AtomicAttribute2023.isoDocType,
            namespaces = mapOf(
                AtomicAttribute2023.isoNamespace to ItemsRequestList(
                    listOf(SingleItemsRequest(AtomicAttribute2023.CLAIM_GIVEN_NAME, false))
                )
            ),
        )
    )
)

private fun deviceRequest(vararg docRequests: DocRequest) = DeviceRequest(Version(1, 0), arrayOf(*docRequests))

private fun sha256(input: ByteArray) = Digest.SHA256.digest(input).encodeToString(Base64UrlStrict)

/** The presented SD-JWT of the only other document of [this], and the names of the claims it discloses. */
private fun PresentationResponseParameters.DeviceRetrievalParameters.presentedSdJwt(): Pair<SdJwtSigned, List<String>> {
    val document = deviceResponse.otherDocuments.shouldNotBeNull().shouldBeSingleton().single()
    document.docFormat shouldBe DocRequestInfo.DOC_FORMAT_SD_JWT
    val compact = DefaultZlibService().decompress(document.data).shouldNotBeNull().decodeToString()
    val sdJwt = SdJwtSigned.parseCatching(compact).getOrThrow()
    val names = sdJwt.rawDisclosures.map {
        Json.parseToJsonElement(it.decodeToByteArray(Base64UrlStrict).decodeToString()).jsonArray
    }.map { if (it.size == 3) it[1].jsonPrimitive.content else "[${it[1].jsonPrimitive.content}]" }
    return sdJwt to names
}

val AgentIsoSdJwtTest by matrixSuite {

    fixture {
        object {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            )
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(holderKeyMaterial)

            suspend fun storeSdJwt() = holder.storeCredential(
                issuer.issueCredential(
                    CredentialToBeIssued.VcSd(
                        claims = listOf(
                            ClaimToBeIssued("given_name", "Susanne"),
                            ClaimToBeIssued(
                                "address", listOf(
                                    ClaimToBeIssued("postal_code", "1010"),
                                    ClaimToBeIssued("locality", "Wien"),
                                )
                            ),
                            ClaimToBeIssued(
                                "nationalities", listOf(
                                    ClaimToBeIssuedArrayElement("AT"),
                                    ClaimToBeIssuedArrayElement("DE"),
                                )
                            ),
                        ),
                        expiration = Clock.System.now() + 1.minutes,
                        scheme = AtomicAttribute2023,
                        subjectPublicKey = holderKeyMaterial.publicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                        sdAlgorithm = supportedSdAlgorithms.random(),
                    )
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            suspend fun present(request: DeviceRequest) = holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = "not used",
                    audience = "not used",
                    calcIsoSessionTranscript = { transcript },
                ),
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(request),
            )
        }
    } - {

        "an SD-JWT VC is presented in otherDocuments, bound to the session transcript, without reader authentication" {
            it.storeSdJwt()
            val response = it.present(deviceRequest(sdJwtDocRequest("given_name", "postal_code")))
                .getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            response.deviceResponse.documents?.size shouldBe 0
            response.deviceResponse.otherDocuments.shouldNotBeNull().single().docRequestIds shouldBe listOf(0U)
            val (sdJwt, disclosed) = response.presentedSdJwt()
            disclosed.toSet() shouldBe setOf("given_name", "address", "postal_code")
            val keyBinding = sdJwt.keyBindingJws.shouldNotBeNull().payload
            keyBinding.challenge shouldBe sha256(transcript.sessionTranscriptBytes())
            keyBinding.audience shouldBe IsoSdJwtKeyBinding.AUDIENCE_WITHOUT_READER_AUTHENTICATION
        }

        "the audience is the hash of the reader authentication of the document request" {
            it.storeSdJwt()
            val readerAuth = SignCose<ByteArray>(EphemeralKeyWithoutCert())(
                null, null, null, ByteArraySerializer()
            ).getOrThrow()
            val response = it.present(deviceRequest(sdJwtDocRequest("given_name", readerAuth = readerAuth)))
                .getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            response.presentedSdJwt().first.keyBindingJws.shouldNotBeNull().payload.audience shouldBe
                    sha256(coseCompliantSerializer.encodeToByteArray(readerAuth))
        }

        "array components select an index or every element" {
            it.storeSdJwt()

            it.present(deviceRequest(sdJwtDocRequest("first_nationality"))).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .presentedSdJwt().second shouldContainExactlyInAnyOrder listOf("nationalities", "[AT]")
            it.present(deviceRequest(sdJwtDocRequest("nationalities"))).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .presentedSdJwt().second shouldContainExactlyInAnyOrder listOf("nationalities", "[AT]", "[DE]")
        }

        "an alternative set is presented for a missing requested element, in the order of preference" {
            it.storeSdJwt()
            val alternatives = listOf(
                AlternativeDataElementsSet(
                    requestedElement = ElementReference(SD_JWT_NAMESPACE, "missing"),
                    alternativeElementSets = listOf(
                        listOf(ElementReference(SD_JWT_NAMESPACE, "locality")),
                        listOf(ElementReference(SD_JWT_NAMESPACE, "postal_code")),
                    ),
                )
            )

            it.present(deviceRequest(sdJwtDocRequest("missing", alternatives = alternatives))).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .presentedSdJwt().second.toSet() shouldBe setOf("address", "locality")
        }

        "an mdoc and an SD-JWT VC are presented in one response" {
            it.storeSdJwt()
            DummyCredentialDataProvider.issueAndStoreIsoMdoc(it.holder, it.holderKeyMaterial, it.issuer)
            val response = it.present(deviceRequest(mdocDocRequest(), sdJwtDocRequest("given_name")))
                .getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            response.deviceResponse.documents.shouldNotBeNull().shouldBeSingleton()
            response.deviceResponse.otherDocuments.shouldNotBeNull().single().docRequestIds shouldBe listOf(1U)
        }

        "an SD-JWT VC of another vct, a missing claim, or claims in another namespace do not match" {
            it.storeSdJwt()

            listOf(
                sdJwtDocRequest("given_name", docType = "urn:example:other"),
                sdJwtDocRequest("missing"),
                sdJwtDocRequest("not_mapped"),
                sdJwtDocRequest("given_name", namespace = AtomicAttribute2023.isoNamespace),
            ).forEach { docRequest ->
                it.present(deviceRequest(docRequest)).isFailure shouldBe true
            }
        }

        "an mdoc request does not return other documents" {
            DummyCredentialDataProvider.issueAndStoreIsoMdoc(it.holder, it.holderKeyMaterial, it.issuer)
            it.present(deviceRequest(mdocDocRequest())).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                .deviceResponse.otherDocuments.shouldBeNull()
        }
    }
}
