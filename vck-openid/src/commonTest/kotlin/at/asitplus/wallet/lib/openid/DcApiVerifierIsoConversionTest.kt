package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.TransactionData
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements.GIVEN_NAME
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedCredentialSet
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.AGE_OVER_18
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements.BIRTH_DATE
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

val DcApiVerifierIsoConversionTest by matrixSuite {
    val ageOver18 = MdocClaimReference(MDL_NAMESPACE, AGE_OVER_18)
    val birthDate = MdocClaimReference(MDL_NAMESPACE, BIRTH_DATE)
    // their content does not matter here, the wallet validates them
    val wrprcJwt = "eyJhbGciOiJFUzI1NiJ9.e30.c2lnbmF0dXJl"
    val wrprcCwt = byteArrayOf(0xD2.toByte(), 0x84.toByte(), 0x40, 0xA0.toByte(), 0xF6.toByte(), 0x40)

    fixture { StoreRecordingVerifier() } - {
        test("a request the ISO conversion can express creates state for both exchange protocols") {
            val request = RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18)

            it.createForBothProtocols(request).getOrThrow()

            it.storedAuthnRequests.putKeys.shouldNotBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldNotBeEmpty()
        }

        test("a request the ISO conversion can not express creates no state for any exchange protocol") {
            val request = RequestedCredential.SdJwt(EU_PID_SD_JWT_VCT, JsonClaimReference(GIVEN_NAME))

            it.createForBothProtocols(request).apply {
                exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "mso_mdoc"
            }

            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("a request with transaction data offered over Annex C creates no state for any exchange protocol") {
            val request = RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18, id = "mdl")
            val transactionData = QCertCreationAcceptance(
                qcTermsConditionsUri = "https://example.com/terms",
                qcHash = byteArrayOf(1, 2, 3),
                qcHashAlgorithmOid = ObjectIdentifier("1.2.3.4"),
                credentialIds = setOf("mdl"),
            )

            val result = it.createForBothProtocols(request, listOf(transactionData))

            result.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "Transaction data"
            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("the CWT of the registration certificate is the euWrprc of every document request of Annex C") {
            val request = RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18)
            val registrationCertificate = RelyingPartyRegistrationCertificate(jwt = wrprcJwt, cwt = wrprcCwt)

            it.createForBothProtocols(request, registrationCertificate = registrationCertificate).getOrThrow()

            it.storedIsoMdocRequest().deviceRequest.docRequests.single()
                .itemsRequest.value.requestInfo.shouldNotBeNull().euWrprc shouldBe wrprcCwt
        }

        test("a registration certificate without the CWT offered over Annex C creates no state for any protocol") {
            val request = RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18)

            val result = it.createForBothProtocols(
                request,
                registrationCertificate = RelyingPartyRegistrationCertificate(jwt = wrprcJwt),
            )

            result.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "CWT"
            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("a registration certificate without the JWT offered over OpenID4VP creates no state for any protocol") {
            val request = RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18)

            val result = it.createForBothProtocols(
                request,
                registrationCertificate = RelyingPartyRegistrationCertificate(cwt = wrprcCwt),
            )

            result.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "JWT"
            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("a typed request offered over both is its DCQL query and its DeviceRequest with purpose hints") {
            val purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_AGE_VERIFICATION)
            val presentation = RequestedPresentation(
                RequestedCredentialSet(
                    options = listOf(setOf(RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18))),
                    purposeHints = purposeHints,
                )
            )
            val options = DcApiRequestOptions(
                presentation,
                expectedOrigins = listOf("https://example.com"),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
            )

            it.create(options, DcApiCreationOptions.OpenId4VpUnsigned, DcApiCreationOptions.Iso180137AnnexC)
                .getOrThrow()

            it.storedAuthnRequest().dcqlQuery shouldBe
                    CredentialPresentationRequestBuilder(presentation).toDCQLRequest().dcqlQuery
            it.storedIsoMdocRequest().deviceRequest.deviceRequestInfo.shouldNotBeNull()
                .value.useCases.shouldNotBeNull().single().purposeHints shouldBe purposeHints
        }

        test("a typed request is converted only for the offered protocols") {
            val presentation = RequestedPresentation.allOf(
                RequestedCredential.SdJwt(EU_PID_SD_JWT_VCT, JsonClaimReference(GIVEN_NAME))
            )
            val options = DcApiRequestOptions(
                presentation,
                expectedOrigins = listOf("https://example.com"),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
            )

            val result = it.create(options, DcApiCreationOptions.OpenId4VpUnsigned)

            result.isSuccess shouldBe true
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("a raw DeviceRequest offered over OpenID4VP creates no state for any protocol") {
            val deviceRequest = RequestedPresentation.allOf(
                RequestedCredential.Mdoc(MDL_DOCTYPE, ageOver18)
            ).toDeviceRequest()
            val options = DcApiRequestOptions(
                presentationRequest = DcApiPresentationRequest.Raw(
                    CredentialPresentationRequest.IsoDeviceRetrieval(deviceRequest)
                ),
                expectedOrigins = listOf("https://example.com"),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
            )

            val result = it.create(
                options,
                DcApiCreationOptions.OpenId4VpUnsigned,
                DcApiCreationOptions.Iso180137AnnexC,
            )

            result.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "OpenID4VP"
            it.storedEphemeralKeys.putKeys.shouldBeEmpty()
            it.storedAuthnRequests.putKeys.shouldBeEmpty()
            it.storedIsoMdocRequests.putKeys.shouldBeEmpty()
        }

        test("an mdoc with alternative data elements is offered over both, ISO requesting them as alternatives") {
            val request = RequestedCredential.Mdoc(
                MDL_DOCTYPE,
                ClaimSelection.Alternatives(setOf(ageOver18), setOf(birthDate)),
            )

            it.createForBothProtocols(request).getOrThrow()

            it.storedAuthnRequests.putKeys.shouldNotBeEmpty()
            it.storedIsoMdocRequest().deviceRequest.docRequests.single().itemsRequest.value.apply {
                namespaces shouldBe mapOf(
                    MDL_NAMESPACE to ItemsRequestList(listOf(SingleItemsRequest(AGE_OVER_18, false)))
                )
                requestInfo.shouldNotBeNull().alternativeDataElements shouldBe listOf(
                    AlternativeDataElementsSet(
                        requestedElement = ElementReference(MDL_NAMESPACE, AGE_OVER_18),
                        alternativeElementSets = listOf(listOf(ElementReference(MDL_NAMESPACE, BIRTH_DATE))),
                    )
                )
            }
        }

        test("an mdoc with data elements if available is offered over both, ISO requesting the required ones") {
            val request = RequestedCredential.Mdoc(
                MDL_DOCTYPE,
                ClaimSelection.All(required = setOf(ageOver18), ifAvailable = setOf(birthDate)),
            )

            it.createForBothProtocols(request).getOrThrow()

            it.storedAuthnRequests.putKeys.shouldNotBeEmpty()
            it.storedIsoMdocRequest().deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe
                    mapOf(MDL_NAMESPACE to ItemsRequestList(listOf(SingleItemsRequest(AGE_OVER_18, false))))
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

    /**
     * Offers [credential], with [transactionData] and [registrationCertificate], over OpenID4VP and ISO/IEC 18013-7
     * Annex C in one browser call.
     */
    suspend fun createForBothProtocols(
        credential: RequestedCredential,
        transactionData: List<TransactionData>? = null,
        registrationCertificate: RelyingPartyRegistrationCertificate? = null,
    ) = create(
        DcApiRequestOptions(
            presentationRequest = DcApiPresentationRequest.Raw(
                CredentialPresentationRequestBuilder(credential).toDCQLRequest()
            ),
            responseMode = OpenIdConstants.ResponseMode.DcApi,
            expectedOrigins = listOf("https://example.com"),
            transactionData = transactionData,
            registrationCertificate = registrationCertificate,
        ),
        DcApiCreationOptions.OpenId4VpUnsigned,
        DcApiCreationOptions.Iso180137AnnexC,
    )

    /** Offers the request of [options] over [creationOptions]. */
    suspend fun create(options: DcApiRequestOptions, vararg creationOptions: DcApiCreationOptions) =
        verifier.createAuthnRequest(options, *creationOptions)

    /** The single OpenID4VP request stored. */
    suspend fun storedAuthnRequest(): AuthenticationRequestParameters =
        storedAuthnRequests.get(storedAuthnRequests.putKeys.single())
            .shouldBeInstanceOf<AuthenticationRequestParameters>()

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
