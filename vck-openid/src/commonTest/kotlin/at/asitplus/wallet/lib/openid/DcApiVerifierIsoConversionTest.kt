package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.OpenIdConstants
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

val DcApiVerifierIsoConversionTest by matrixSuite {
    val ageOver18 = MdocClaimReference("org.iso.18013.5.1", "age_over_18")
    val birthDate = MdocClaimReference("org.iso.18013.5.1", "birth_date")

    fixture { StoreRecordingVerifier() } - {
        test("a request the ISO conversion can express creates state for both exchange protocols") {
            val request = RequestedCredential.Mdoc("org.iso.18013.5.1.mDL", ageOver18)

            val result = it.createForBothProtocols(request)

            result.isSuccess shouldBe true
            it.storedAuthnRequests.putKeys.shouldNotBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldNotBeEmpty()
        }

        test("a request the ISO conversion can not express creates no state for any exchange protocol") {
            val request = RequestedCredential.Mdoc(
                "org.iso.18013.5.1.mDL",
                ClaimSelection.Alternatives(setOf(ageOver18), setOf(birthDate)),
            )

            val result = it.createForBothProtocols(request)

            result.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "claim combinations"
            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("an mdoc with data elements if available is offered over both, ISO requesting the required ones") {
            val request = RequestedCredential.Mdoc(
                "org.iso.18013.5.1.mDL",
                ClaimSelection.All(required = setOf(ageOver18), ifAvailable = setOf(birthDate)),
            )

            val result = it.createForBothProtocols(request)

            result.isSuccess shouldBe true
            it.storedAuthnRequests.putKeys.shouldNotBeEmpty()
            it.storedIsoMdocRequest().deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe
                    mapOf("org.iso.18013.5.1" to ItemsRequestList(listOf(SingleItemsRequest("age_over_18", false))))
        }
    }
}

/** A [DcApiVerifier] whose state stores record what it puts into them. */
private class StoreRecordingVerifier {
    val storedEphemeralKeys = RecordingMapStore<String, String>()
    val storedAuthnRequests = RecordingMapStore<String, Any>()
    val storedIsoMdocRequests = RecordingMapStore<String, Any>()
    val verifier = DcApiVerifier(
        keyMaterial = EphemeralKeyWithoutCert(),
        clientIdScheme = ClientIdScheme.PreRegistered(
            clientId = "dc-api-rp-${uuid4()}",
            redirectUri = "https://example.com/callback",
        ),
        ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(storedEphemeralKeys),
        stateToAuthnRequestStore = storedAuthnRequests.typed(),
        stateToIsoMdocRequestStore = storedIsoMdocRequests.typed(),
        presentationPolicy = testPresentationPolicy,
    )

    /** Offers [credential] over OpenID4VP and ISO/IEC 18013-7 Annex C in one browser call. */
    suspend fun createForBothProtocols(credential: RequestedCredential) = verifier.createAuthnRequest(
        OpenId4VpRequestOptions(
            presentationRequest = CredentialPresentationRequestBuilder(credential).toDCQLRequest(),
            responseMode = OpenIdConstants.ResponseMode.DcApi,
            expectedOrigins = listOf("https://example.com"),
        ),
        DcApiCreationOptions.OpenId4VpUnsigned,
        DcApiCreationOptions.Iso180137AnnexC,
    )

    /** The single ISO/IEC 18013-7 Annex C request stored. */
    suspend fun storedIsoMdocRequest(): IsoMdocRequest =
        storedIsoMdocRequests.get(storedIsoMdocRequests.putKeys.single()).shouldBeInstanceOf<IsoMdocRequest>()
}

/** A [MapStore] in memory that records the keys values are put for. */
private class RecordingMapStore<T, U> : MapStore<T, U> {
    private val delegate = DefaultMapStore<T, U>()
    val putKeys = mutableListOf<T>()

    override suspend fun put(key: T, value: U) {
        putKeys += key
        delegate.put(key, value)
    }

    override suspend fun get(key: T): U? = delegate.get(key)

    override suspend fun remove(key: T): U? = delegate.remove(key)

    @Suppress("UNCHECKED_CAST")
    fun <V> typed(): MapStore<T, V> = this as MapStore<T, V>
}
