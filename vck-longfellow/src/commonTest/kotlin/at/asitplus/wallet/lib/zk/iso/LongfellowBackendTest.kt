package at.asitplus.wallet.lib.zk.iso

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.ZkRequest
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialQuery
import at.asitplus.openid.dcql.DCQLIsoMdocZkSystemSpec
import at.asitplus.openid.dcql.DCQLIsoMdocZkSystemType
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.truncateToSeconds
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupid.EU_PID_METADATA_URL
import at.asitplus.wallet.eupid.EuPidDataElements
import at.asitplus.wallet.eupid.EuPidItemValueSerializerMap
import at.asitplus.wallet.eupid.EuPidJsonValueEncoder
import at.asitplus.wallet.eupid.EuPidMetadataDocument
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.StaticCredentialMetadataRegistry
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.zk.iso.LongfellowBackend.Companion.BLOCK_ENC_HASH_KEY
import at.asitplus.wallet.lib.zk.iso.LongfellowBackend.Companion.CIRCUIT_HASH_KEY
import at.asitplus.wallet.lib.zk.iso.LongfellowBackend.Companion.NUM_ATTRIBUTES_KEY
import at.asitplus.wallet.lib.zk.iso.LongfellowBackend.Companion.VERSION_KEY
import at.asitplus.wallet.sdjwt.SdJwtTypeMetadataDocumentRegistry
import com.benasher44.uuid.uuid4
import io.github.z4kn4fein.semver.Version
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldBeUnique
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.serializer
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

private const val LONGFELLOW_SYSTEM = "longfellow-libzk-v1"
private const val SINGLE_ATTRIBUTE_SPEC_ID = "my-custom-id-5"
private const val SINGLE_ATTRIBUTE_CIRCUIT_HASH =
    "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"

private const val TEST_CIRCUIT_HASH = "hash-123"
private const val TEST_VERSION = 1L
private const val TEST_NUM_ATTRIBUTES = 5L
private const val TEST_BLOCK_ENC_HASH = 100L
private const val TEST_EXTRA_PARAM_KEY = "extra_key"
private const val TEST_EXTRA_PARAM_VALUE = "extra_value"

val LongfellowBackendTest by matrixSuite {
    fixture {
        LibraryInitializer.registerCredentialMetadataRegistry(
            StaticCredentialMetadataRegistry(
                documentRegistry = SdJwtTypeMetadataDocumentRegistry(
                    EuPidMetadataDocument,
                ),
                documentUrls = mapOf(
                    EuPidMetadataDocument.first to EU_PID_METADATA_URL,
                )
            )
        )

        LibraryInitializer.registerCredentialSerializers(
            jsonValueEncoder = EuPidJsonValueEncoder,
            itemValueSerializerMap = EuPidItemValueSerializerMap + mapOf(
                EU_PID_DOCTYPE to ((EuPidItemValueSerializerMap[EU_PID_DOCTYPE] ?: emptyMap()) +
                        (EuPidDataElements.GIVEN_NAME to String.serializer()))
            ),
        )

        runBlocking {
            val holderKey = EphemeralKeyWithoutCert()
            val backendRegistry = IsoMdocZkBackendRegistry()
            val zkEngine = IsoMdocZkEngine(backendRegistry)
            val holder = HolderAgent(
                keyMaterial = holderKey,
                mdocZkEngine = zkEngine,
            )
            val givenName = "Susanne"
            val requestedPath = DCQLClaimsPathPointer(EU_PID_DOCTYPE, EuPidDataElements.GIVEN_NAME)
            val credentialScheme = AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
                as IsoMdocCredentialScheme

            val zkSystemType = DCQLIsoMdocZkSystemType(
                zkRequired = true,
                systemSpecs = listOf(
                    DCQLIsoMdocZkSystemSpec(
                        id = SINGLE_ATTRIBUTE_SPEC_ID,
                        system = LONGFELLOW_SYSTEM,
                        circuitHash = SINGLE_ATTRIBUTE_CIRCUIT_HASH,
                        numAttributes = 1,
                        version = 7,
                        blockEncHash = 4151,
                        blockEncSig = 4096,
                    )
                ),
            )
            val dcqlZkRequest = CredentialPresentationRequest.DCQLRequest(
                DCQLQuery(
                    credentials = DCQLCredentialQueryList(nonEmptyListOf(
                        DCQLIsoMdocZkCredentialQuery(
                            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                            meta = DCQLIsoMdocZkCredentialMetadataAndValidityConstraints(
                                doctypeValue = EU_PID_DOCTYPE,
                                zkSystemType = zkSystemType,
                            ),
                            claims = DCQLClaimsQueryList(nonEmptyListOf(
                                DCQLIsoMdocClaimsQuery(path = requestedPath)
                            )),
                        )
                    )),
                )
            )
            val zkRequest = zkSystemType.toZkRequest()

            val deviceRequest = DeviceRequest(
                parsedVersion = Version(1, 0),
                docRequests = arrayOf(
                    DocRequest(
                        itemsRequest = ByteStringWrapper(
                            ItemsRequest(
                                docType = EU_PID_DOCTYPE,
                                namespaces = mapOf(
                                    credentialScheme.isoNamespace to ItemsRequestList(
                                        listOf(SingleItemsRequest(EuPidDataElements.GIVEN_NAME, false))
                                    )
                                ),
                                requestInfo = DocRequestInfo(zkRequest = zkRequest),
                            )
                        )
                    )
                )
            )

            holder.storeCredential(
                IssuerAgent(
                    keyMaterial = EphemeralKeyWithSelfSignedCert(),
                    identifier = "https://issuer.example.com/${uuid4()}".toUri(),
                    randomSource = RandomSource.Default,
                ).issueCredential(
                    CredentialToBeIssued.Iso(
                        issuerSignedItems = listOf(
                            IssuerSignedItem(
                                digestId = 0U,
                                random = ByteArray(16) { it.toByte() },
                                elementIdentifier = EuPidDataElements.GIVEN_NAME,
                                elementValue = givenName,
                            )
                        ),
                        expiration = Clock.System.now().plus(120.minutes).truncateToSeconds(),
                        scheme = credentialScheme,
                        subjectPublicKey = holderKey.publicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(
                            OidcUserInfo("subject")
                        ).getOrThrow(),
                    )
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            object {
                val holder = holder
                val backendRegistry = backendRegistry
                val zkEngine = zkEngine
                val dcqlZkRequest = dcqlZkRequest
                val zkRequest = zkRequest
                val deviceRequest = deviceRequest
                val givenName = givenName
            }
        }
    } - {
        test("creates a ZK DeviceResponse for one requested attribute") {
            it.backendRegistry.register(LongfellowBackend()).getOrThrow()

            val sessionTranscript = SessionTranscript.forQr(
                deviceEngagementBytes = byteArrayOf(),
                eReaderKeyBytes = byteArrayOf(),
            )

            val response = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = uuid4().toString(),
                    audience = "https://verifier.example.com",
                    calcIsoSessionTranscript = { sessionTranscript },
                ),
                credentialPresentationRequest = it.dcqlZkRequest,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val presentation = response.verifiablePresentations.values
                .shouldBeSingleton()
                .single()
                .shouldBeSingleton()
                .single()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
            val deviceResponse = presentation.deviceResponse

            assertZkDeviceResponse(deviceResponse, it.givenName, it.zkEngine, sessionTranscript, it.zkRequest)
        }

        test("creates a ZK DeviceResponse from a DeviceRequest") {
            it.backendRegistry.register(LongfellowBackend()).getOrThrow()

            val sessionTranscript = SessionTranscript.forQr(
                deviceEngagementBytes = byteArrayOf(),
                eReaderKeyBytes = byteArrayOf(),
            )

            val response = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = uuid4().toString(),
                    audience = "https://verifier.example.com",
                    calcIsoSessionTranscript = { sessionTranscript },
                ),
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                    it.deviceRequest
                ),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            assertZkDeviceResponse(response.deviceResponse, it.givenName, it.zkEngine, sessionTranscript, it.zkRequest)
        }

        test("uninitialized ZkSystem throws IllegalStateException on use") {
            val backend = LongfellowBackend()

            shouldThrow<IllegalStateException> {
                backend.zkSystemSpecs
            }

            shouldThrow<IllegalStateException> {
                backend.system
            }

            val dummySpec = ZkSystemSpec(
                id = uuid4().toString(),
                system = uuid4().toString(),
                params = emptyMap()
            )
            shouldThrow<IllegalStateException> {
                backend.supports(dummySpec)
            }
        }

        test("concurrent and repeat initialization is safe and thread-safe") {
            val backend = LongfellowBackend()
            val jobRange = (1..50)

            coroutineScope {
                // Launch concurrent initialization calls alongside readers on multi-threaded dispatcher
                val initJobs = jobRange.map {
                    async(Dispatchers.Default) {
                        backend.initialize()
                    }
                }

                val readerJobs = jobRange.map {
                    async(Dispatchers.Default) {
                        // Wait for any init to complete then verify memory visibility across background workers
                        initJobs.first().await()
                        backend.zkSystemSpecs.isNotEmpty() && backend.system.isNotEmpty()
                    }
                }

                val initResults = initJobs.awaitAll()
                val readerResults = readerJobs.awaitAll()

                initResults.all { it.isSuccess } shouldBe true
                readerResults.all { it } shouldBe true
            }
        }

        test("LongfellowZkBackend supports all self-advertised ZkSystemSpecs") {
            val backend = LongfellowBackend()
            backend.initialize().getOrThrow()
            backend.zkSystemSpecs.forEach {
                backend.supports(it) shouldBe true
            }
        }

        test("LongfellowZkBackend ZkSystemSpecs have unique IDs") {
            val backend = LongfellowBackend()
            backend.initialize().getOrThrow()
            backend.zkSystemSpecs.map { it.id }.shouldBeUnique()
        }


        test("LongfellowZkBackend ZkSystemSpecs feature a unique circuit_hash") {
            val backend = LongfellowBackend()
            backend.initialize().getOrThrow()
            backend.zkSystemSpecs.map {
                val circuitHash = it.params[CIRCUIT_HASH_KEY]
                circuitHash.shouldBeInstanceOf<String>()
                circuitHash
            }.shouldBeUnique()
        }

        test("LongfellowZkBackend ZkSystemSpecs use the backend's system name") {
            val backend = LongfellowBackend()
            backend.initialize().getOrThrow()
            val systemName = backend.system
            backend.zkSystemSpecs.forEach {
                it.system shouldBe systemName
            }
        }

        test("Internal ZkSystemSpec representation can be converted to Multipaz ZkSystemSpec representation and vice versa") {
            val backend = LongfellowBackend()
            backend.initialize().getOrThrow()
            val zkSystemSpecs = backend.zkSystemSpecs
            val convertedZkSystemSpecs =  backend.zkSystemSpecs.map { it.toMultipazZkSystemSpec() }.map { it.toZkSystemSpec() }
            zkSystemSpecs shouldBe convertedZkSystemSpecs
        }

        test("toMultipazZkSystemSpec supports all primitive types and conversions") {
            val keyString = "str_key"
            val keyBool = "bool_key"
            val keyDouble = "double_key"
            val keyFloat = "float_key"
            val keyLong = "long_key"
            val keyInt = "int_key"
            val keyShort = "short_key"
            val keyByte = "byte_key"

            val original = ZkSystemSpec(
                id = "spec-primitives",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    keyString to "hello",
                    keyBool to true,
                    keyDouble to 3.14,
                    keyFloat to 2.71f,
                    keyLong to 100L,
                    keyInt to 42,
                    keyShort to 5.toShort(),
                    keyByte to 1.toByte()
                )
            )

            val multipaz = original.toMultipazZkSystemSpec()
            val roundtripped = multipaz.toZkSystemSpec()

            roundtripped.id shouldBe original.id
            roundtripped.system shouldBe original.system
            roundtripped.params[keyString] shouldBe original.params[keyString]
            roundtripped.params[keyBool] shouldBe original.params[keyBool]
            roundtripped.params[keyDouble] shouldBe original.params[keyDouble]
            roundtripped.params[keyFloat] shouldBe original.params[keyFloat]
            roundtripped.params[keyLong] shouldBe original.params[keyLong]
            roundtripped.params[keyInt] shouldBe original.params[keyInt]
            roundtripped.params[keyShort] shouldBe original.params[keyShort]
            roundtripped.params[keyByte] shouldBe original.params[keyByte]
        }

        test("toMultipazZkSystemSpec throws IllegalArgumentException for unsupported parameter types") {
            val invalidSpec = ZkSystemSpec(
                id = "spec-unsupported-type",
                system = LONGFELLOW_SYSTEM,
                params = mapOf("unsupported_list" to listOf("a", "b"))
            )

            shouldThrow<IllegalArgumentException> {
                invalidSpec.toMultipazZkSystemSpec()
            }
        }

        test("matchesPerfectly and isSatisfiedBy predicates work as expected") {
            val target = ZkSystemSpec(
                id = "target-spec",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to TEST_VERSION,
                    NUM_ATTRIBUTES_KEY to TEST_NUM_ATTRIBUTES
                )
            ).toMultipazZkSystemSpec()

            val exactCandidate = ZkSystemSpec(
                id = "cand-exact",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to TEST_VERSION,
                    NUM_ATTRIBUTES_KEY to TEST_NUM_ATTRIBUTES
                )
            ).toMultipazZkSystemSpec()

            val underspecifiedCandidate = ZkSystemSpec(
                id = "cand-underspecified",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to TEST_VERSION
                )
            ).toMultipazZkSystemSpec()

            val candidateWithoutHash = ZkSystemSpec(
                id = "cand-no-hash",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(VERSION_KEY to TEST_VERSION)
            ).toMultipazZkSystemSpec()

            val candidateWrongVal = ZkSystemSpec(
                id = "cand-wrong-val",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to 99L
                )
            ).toMultipazZkSystemSpec()

            val candidateExtraParam = ZkSystemSpec(
                id = "cand-extra-param",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to TEST_VERSION,
                    NUM_ATTRIBUTES_KEY to TEST_NUM_ATTRIBUTES,
                    TEST_EXTRA_PARAM_KEY to TEST_EXTRA_PARAM_VALUE
                )
            ).toMultipazZkSystemSpec()

            exactCandidate.matchesExactly(target) shouldBe true
            exactCandidate.isCompatibleWith(target) shouldBe true

            underspecifiedCandidate.matchesExactly(target) shouldBe false
            underspecifiedCandidate.isCompatibleWith(target) shouldBe true

            candidateWithoutHash.isCompatibleWith(target) shouldBe false
            candidateWithoutHash.matchesExactly(target) shouldBe false
            candidateWrongVal.isCompatibleWith(target) shouldBe false
            candidateWrongVal.matchesExactly(target) shouldBe false
            candidateExtraParam.isCompatibleWith(target) shouldBe false
            candidateExtraParam.matchesExactly(target) shouldBe false
        }

        test("best match resolution prioritizes candidates with the most matching parameters order-independently") {
            val target = ZkSystemSpec(
                id = "target",
                system = LONGFELLOW_SYSTEM,
                params = mapOf(
                    CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH,
                    VERSION_KEY to TEST_VERSION,
                    NUM_ATTRIBUTES_KEY to TEST_NUM_ATTRIBUTES,
                    BLOCK_ENC_HASH_KEY to TEST_BLOCK_ENC_HASH
                )
            ).toMultipazZkSystemSpec()

            val candMinimal = ZkSystemSpec("id-min", LONGFELLOW_SYSTEM, mapOf(CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH)).toMultipazZkSystemSpec()
            val candMedium = ZkSystemSpec("id-med", LONGFELLOW_SYSTEM, mapOf(CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH, VERSION_KEY to TEST_VERSION)).toMultipazZkSystemSpec()
            val candRich = ZkSystemSpec("id-rich", LONGFELLOW_SYSTEM, mapOf(CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH, VERSION_KEY to TEST_VERSION, NUM_ATTRIBUTES_KEY to TEST_NUM_ATTRIBUTES)).toMultipazZkSystemSpec()

            val candidatesInRandomOrder = listOf(candMinimal, candRich, candMedium)

            val bestMatch = candidatesInRandomOrder
                .filter { it.isCompatibleWith(target) }
                .maxByOrNull { it.params.size }

            bestMatch?.id shouldBe "id-rich"
            bestMatch?.params?.size shouldBe 3
        }

        test("copyWithParameters replaces id and preserves all parameter values") {
            val oldId = "old-id"
            val newId = "new-id"

            val original = ZkSystemSpec(
                id = oldId,
                system = LONGFELLOW_SYSTEM,
                params = mapOf(CIRCUIT_HASH_KEY to TEST_CIRCUIT_HASH, VERSION_KEY to TEST_VERSION)
            ).toMultipazZkSystemSpec()

            val copied = original.copyWithParameters(id = newId)

            copied.id shouldBe newId
            copied.system shouldBe original.system
            copied.params shouldBe original.params
        }
    }
}

private fun assertZkDeviceResponse(
    deviceResponse: at.asitplus.iso.DeviceResponse,
    givenName: String,
    zkEngine: IsoMdocZkEngine,
    sessionTranscript: SessionTranscript,
    zkRequest: ZkRequest
) {
    deviceResponse.documents.orEmpty().size shouldBe 0
    val zkDocument = deviceResponse.zkDocuments.orEmpty().shouldBeSingleton().single()
    zkDocument.proof.isNotEmpty() shouldBe true
    zkDocument.zkDocumentDataBytes.value.zkSystemId shouldBe SINGLE_ATTRIBUTE_SPEC_ID
    zkDocument.zkDocumentDataBytes.value.issuerSigned
        ?.get(EU_PID_DOCTYPE)
        ?.entries
        ?.shouldBeSingleton()
        ?.single()
        ?.apply {
            elementIdentifier shouldBe EuPidDataElements.GIVEN_NAME
            elementValue.toString() shouldBe givenName
        }
        .shouldNotBeNull()

    val zkSystemSpec = zkRequest.systemSpecs.first { it.id == zkDocument.zkDocumentDataBytes.value.zkSystemId }

    val isoMdocZkProofs = deviceResponse.zkDocuments?.map {
        zkEngine.load(zkSystemSpec, it, sessionTranscript).getOrThrow()
    }.also {
        it.shouldNotBeNull()
        it.shouldBeSingleton()
    }
    runBlocking { isoMdocZkProofs!!.all { it.verify().isSuccess } shouldBe true }

}
