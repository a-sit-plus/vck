package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkRequest
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.AtomicAttribute2025
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.KSerializer
import kotlin.random.Random
import kotlin.time.Clock

val IsoMdocZkEngineTest by matrixSuite {
    fixture {
        val (keyMaterial, storedCredential) = runBlocking { issueAndStoreIsoMdocCredential() }

        object {
            val sessionTranscript = SessionTranscript.forQr(byteArrayOf(), byteArrayOf())
            val zkRegistry = IsoMdocZkBackendRegistry().also { runBlocking { it.register(MockIsoMdocZkBackend) } }
            val zkEngine = IsoMdocZkEngine(registry = zkRegistry)

            val keyMaterial = keyMaterial
            val storedCredential = storedCredential

            val requestedClaims = createIsoMdocZkRequestedClaims(AtomicAttribute2025, AtomicAttribute2025.CLAIM_GIVEN_NAME)

            val request = PresentationRequestParameters(
                nonce = uuid4().toString(),
                audience = uuid4().toString(),
                calcIsoSessionTranscript = { sessionTranscript }
            )
        }
    } - {
        "Successfully routes to backend" {
            // Use custom id names (supported by mock backend)
            val specs = MockIsoMdocZkBackend.zkSystemSpecs.map { spec -> spec.copy(id = "custom-id-${uuid4()}") }

            val isoParams = IsoPresentationParameters.create(
                credential = it.storedCredential,
                claims = it.requestedClaims,
                zkMetadata = ZkMetadata.IsoMdocZk(
                    zkRequest = ZkRequest(zkRequired = true, systemSpecs = specs)
                )
            ).getOrThrow()

            val result = it.zkEngine.generate(it.request, isoParams, it.keyMaterial)
            result.isSuccess shouldBe true
            val proof = result.getOrThrow()
            proof.zkDocument.zkDocumentDataBytes.value.zkSystemId shouldBeIn specs.map { it.id }
            proof.verify()
        }

        "ZkEngine cannot route to backend due to incompatible ZkSystem" {
            val specs = listOf(ZkSystemSpec(
                id = "id-${uuid4()}",
                system = "system-unsupported-by-mock-backend-${uuid4()}",
                params = emptyMap())
            )

            val isoParams = IsoPresentationParameters.create(
                credential = it.storedCredential,
                claims = it.requestedClaims,
                zkMetadata = ZkMetadata.IsoMdocZk(
                    zkRequest = ZkRequest(zkRequired = true, systemSpecs = specs)
                )
            ).getOrThrow()

            val result = it.zkEngine.generate(it.request, isoParams, it.keyMaterial)
            result.isSuccess shouldBe false
        }
    }
}

private suspend fun issueAndStoreIsoMdocCredential(
    attributeKey: String = AtomicAttribute2025.CLAIM_GIVEN_NAME,
    attributeValue: Any = uuid4().toString(),
    credentialScheme: IsoMdocCredentialScheme = AtomicAttribute2025
): Pair<KeyMaterial, StoreEntry.Iso> {
    val keyMaterial = EphemeralKeyWithSelfSignedCert()
    val issuerCredentialStore = InMemoryIssuerCredentialStore()
    val issuerAgent = IssuerAgent(
        keyMaterial = EphemeralKeyWithSelfSignedCert(),
        issuerCredentialStore = issuerCredentialStore,
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    )

    val credentialToBeIssued = DummyCredentialDataProvider.getCredentialForClaim(
        keyMaterial.publicKey,
        credentialScheme,
        ConstantIndex.CredentialRepresentation.ISO_MDOC,
        ClaimToBeIssued(attributeKey, attributeValue)
    ).getOrThrow()

    val issuedDeviceResponse = issuerAgent.issueCredential(credentialToBeIssued).getOrThrow()
    val storeInput = issuedDeviceResponse.toStoreCredentialInput()

    val holderAgent = HolderAgent(keyMaterial = keyMaterial)
    holderAgent.storeCredential(storeInput).getOrThrow()

    val storedCredential = holderAgent.getCredentials()
        ?.filterIsInstance<StoreEntry.Iso>()
        ?.firstOrNull()
        ?: error("Failed to retrieve stored ISO mDoc credential from HolderAgent")

    return Pair(keyMaterial, storedCredential)
}

private fun createIsoMdocZkRequestedClaims(
    credentialScheme: IsoMdocCredentialScheme,
    attributeKey: String
): List<NormalizedJsonPath> = listOf(
    NormalizedJsonPath(
        listOf(
            NormalizedJsonPathSegment.NameSegment(credentialScheme.isoNamespace),
            NormalizedJsonPathSegment.NameSegment(attributeKey)
        )
    )
)

private object MockIsoMdocZkBackend: IsoMdocZkBackend {
    override val system: String = "MockZkSystem.${uuid4()}"

    override val zkSystemSpecs: List<ZkSystemSpec> = listOf(
        ZkSystemSpec(id = "mock-spec-${uuid4()}", system = system, params = emptyMap())
    )

    override val paramSerializers: Map<String, KSerializer<*>> = emptyMap()
    override fun supports(candidate: ZkSystemSpec) = candidate.system == system


    private val mockProof = Random.nextBytes(25)

    override suspend fun generate(
        request: PresentationRequestParameters,
        credential: StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        requestedZkSystemSpecs: List<ZkSystemSpec>,
        keyMaterial: KeyMaterial
    ): KmmResult<IsoMdocZkProof> = catching {
        val selectedSpec = requestedZkSystemSpecs.firstOrNull { supports(it) }
            ?: throw IllegalArgumentException("No ZK system spec available")

        val namespaceToAttributesMap: Map<String, List<String>> = requestedClaims
            .map { claim ->
                val names = claim.segments.filterIsInstance<NormalizedJsonPathSegment.NameSegment>()
                require(names.size == 2) { "Expected claim path to have exactly 2 name segments, but got ${names.size} in path: $claim" }

                names[0].memberName to names[1].memberName
            }
            .groupBy({ it.first }, { it.second })


        val issuerSigned = namespaceToAttributesMap.mapValues { (namespace, attributes) ->
            val wrappedItems = credential.issuerSigned.namespaces?.get(namespace)?.entries

            val items = attributes.map { attributeName ->
                val wrapper = wrappedItems?.find { it.value.elementIdentifier == attributeName }
                    ?: throw PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']")

                ZkSignedItem(attributeName, wrapper.value.elementValue)
            }

            ZkSignedList(items)
        }

        val zkDocument = ZkDocument(
            proof = mockProof,
            zkDocumentDataBytes = ByteStringWrapper(
                ZkDocumentData(
                    docType = credential.schemeIdentifier,
                    zkSystemId = selectedSpec.id,
                    timestamp = Clock.System.now().truncateToSeconds(),
                    issuerSigned = issuerSigned
                )
            )
        )

        IsoMdocZkProof(zkDocument, generateVerify(zkDocument))
    }

    override fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): KmmResult<IsoMdocZkProof> = catching {
        IsoMdocZkProof(zkDocument, generateVerify(zkDocument))
    }

    private fun generateVerify(zkDocument: ZkDocument): () -> KmmResult<Unit> = {
        catching {
            if (!zkDocument.proof.contentEquals(mockProof)) {
                throw IllegalArgumentException("Invalid proof bytes in Mock Backend")
            }
        }

    }

    override suspend fun initialize(): KmmResult<Unit> = KmmResult.success(Unit)
}
