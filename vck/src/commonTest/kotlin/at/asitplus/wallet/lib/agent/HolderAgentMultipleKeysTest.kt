package at.asitplus.wallet.lib.agent

import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import io.github.z4kn4fein.semver.Version
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val HolderAgentMultipleKeysTest by matrixSuite {

    fixture {
        object {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                issuerCredentialStore = InMemoryIssuerCredentialStore(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val first = CountingKeyMaterial(EphemeralKeyWithSelfSignedCert())
            val second = CountingKeyMaterial(EphemeralKeyWithSelfSignedCert())
            val store = InMemorySubjectCredentialStore()
            val resolver = HolderKeyResolver { bound ->
                catching { listOf(first, second).first { it.publicKey == bound } }
            }
            val holder = HolderAgent(holderKeyResolver = resolver, subjectCredentialStore = store)
            val factory = VerifiablePresentationFactory(holderKeyResolver = resolver)
            val request = PresentationRequestParameters(
                nonce = "nonce",
                audience = "https://verifier.example.com/",
                calcIsoSessionTranscript = {
                    SessionTranscript.Qr(deviceEngagementBytes = byteArrayOf(), eReaderKeyBytes = byteArrayOf())
                },
            )

            /** Issues a credential bound to [key] and stores it with a holder of that key. */
            suspend fun storeFor(
                key: KeyMaterial,
                representation: CredentialRepresentation,
                scheme: CredentialScheme = AtomicAttribute2023,
                claim: String = CLAIM_GIVEN_NAME,
            ): StoreEntry = HolderAgent(key, store).storeCredential(
                issuer.issueCredential(
                    if (representation == PLAIN_JWT)
                        DummyCredentialDataProvider.getCredential(key.publicKey, scheme, representation).getOrThrow()
                    else DummyCredentialDataProvider.getCredentialForClaim(
                        key.publicKey, scheme, representation, ClaimToBeIssued(claim, "value"),
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
        }
    } - {

        "SD-JWT VC: each KB-JWT is signed with the key in cnf" - { fixture ->
            listOf(1, 2).asData(nameFn = { "credential bound to key $it" }) test { n ->
                val key = if (n == 1) fixture.first else fixture.second
                val entry = fixture.storeFor(key, SD_JWT)

                val presentation = fixture.factory
                    .createVerifiablePresentation(fixture.request, entry, AllClaimsMatchingResult)
                    .getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

                val keyBinding = presentation.sdJwt.keyBindingJws.shouldNotBeNull()
                VerifyJwsSignature()(keyBinding.jws, key.publicKey).isSuccess.shouldBeTrue()
            }
        }

        "VC-JWT: each presentation is signed with the key the credential is bound to" - { fixture ->
            listOf(1, 2).asData(nameFn = { "credential bound to key $it" }) test { n ->
                val key = if (n == 1) fixture.first else fixture.second
                val entry = fixture.storeFor(key, PLAIN_JWT)

                val presentation = fixture.factory
                    .createVerifiablePresentation(fixture.request, entry, AllClaimsMatchingResult)
                    .getOrThrow().shouldBeInstanceOf<CreatePresentationResult.VpJws>()

                VerifyJwsSignature()(presentation.jwsSigned.jws, key.publicKey).isSuccess.shouldBeTrue()
                presentation.jwsSigned.payload.issuer shouldBe key.publicKey.didEncoded
            }
        }

        test("VC-JWT: one presentation of credentials bound to different keys fails") {
            val credentials = listOf(it.storeFor(it.first, PLAIN_JWT), it.storeFor(it.second, PLAIN_JWT))
                .map { entry -> entry.shouldBeInstanceOf<StoreEntry.Vc>() }

            shouldThrow<PresentationException> { it.factory.createVcPresentation(credentials, it.request) }
        }

        test("ISO mdoc: each document of a device response is signed with the key its credential is bound to") {
            it.storeFor(it.first, ISO_MDOC, AtomicAttribute2023, CLAIM_GIVEN_NAME)
            it.storeFor(it.second, ISO_MDOC, AtomicAttribute2025, CLAIM_FAMILY_NAME)

            val result = it.holder.createDefaultPresentation(
                request = it.request,
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                    DeviceRequest(
                        parsedVersion = Version(1, 0),
                        docRequests = arrayOf(
                            docRequest(AtomicAttribute2023, CLAIM_GIVEN_NAME),
                            docRequest(AtomicAttribute2025, CLAIM_FAMILY_NAME),
                        ),
                    )
                ),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            result.deviceResponse.documents.shouldNotBeNull().shouldHaveSize(2)
            it.first.signatures shouldBe 1
            it.second.signatures shouldBe 1
        }

        test("a credential bound to a key the resolver does not know can't be presented") {
            val entry = it.storeFor(EphemeralKeyWithSelfSignedCert(), SD_JWT)

            it.factory.createVerifiablePresentation(it.request, entry, AllClaimsMatchingResult)
                .exceptionOrNull().shouldBeInstanceOf<PresentationException>()
        }

        test("an SD-JWT VC bound to a key that can't be read, e.g. by kid, can't be presented") {
            val entry = it.storeFor(it.first, SD_JWT).shouldBeInstanceOf<StoreEntry.SdJwt>()
            val byKeyId = entry.copy(sdJwt = entry.sdJwt.copy(confirmationClaim = ConfirmationClaim(keyId = "k1")))

            it.factory.createVerifiablePresentation(it.request, byKeyId, AllClaimsMatchingResult)
                .exceptionOrNull().shouldBeInstanceOf<PresentationException>()
                .message shouldBe "The credential is bound to a holder key that can't be read"
            it.first.signatures shouldBe 0
        }

        test("keyMaterial of a holder with a resolver fails") {
            shouldThrow<UnsupportedOperationException> {
                @Suppress("DEPRECATION")
                it.holder.keyMaterial
            }
            it.holder.holderKeyResolver shouldBe it.resolver
        }
    }
}

/** Counts the signatures created with [key]. */
private class CountingKeyMaterial(private val key: KeyMaterial) : KeyMaterial by key {
    var signatures = 0
        private set

    // Delegation forwards the overloads with a default body as well, so override each one
    override suspend fun sign(data: SignatureInput) = key.sign(data).also { signatures++ }
    override suspend fun sign(data: ByteArray) = key.sign(data).also { signatures++ }
    override suspend fun sign(data: Sequence<ByteArray>) = key.sign(data).also { signatures++ }
}

private fun docRequest(scheme: IsoMdocCredentialScheme, claim: String) = DocRequest(
    itemsRequest = ByteStringWrapper(
        ItemsRequest(
            docType = scheme.isoDocType,
            namespaces = mapOf(
                scheme.isoNamespace to ItemsRequestList(listOf(SingleItemsRequest(claim, false)))
            ),
        )
    )
)
