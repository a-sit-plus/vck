package at.asitplus.wallet.lib.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DocRequest
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.wallet.lib.AbstractMdocVerifier
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.ValidatorMdoc
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.ktor.utils.io.core.toByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

class Iso180137AnnexCVerifier(
    /** Creates challenges in authentication requests. */
    override val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued requests to verify the response to it */
    private val stateToIsoMdocRequestStore: MapStore<String, IsoMdocRequest> = DefaultMapStore(), //stateToRequestStore

    override val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Used to verify session transcripts from mDoc responses. */
    override val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),

    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(),
) : AbstractMdocVerifier() {

    /**
     * Remembers [authenticationRequestParameters] to link responses to requests in [validateResponse].
     *
     * Parameter [externalId] may be used in cases the [authenticationRequestParameters] do not have a `state`
     * parameter, e.g., when using DCAPI.
     */
    suspend fun submitRequest(
        authenticationRequestParameters: IsoMdocRequest,
        externalId: String,
    ) = stateToIsoMdocRequestStore.put(
        key = externalId,
        value = authenticationRequestParameters,
    ).also { Napier.w("Request with external ID $externalId stored") }

    suspend fun createRequest(
        requestOptions: Iso180137AnnexCRequestOptions,
    ): IsoMdocRequest {
        val docRequests = requestOptions.credentials.map {
            val namespace = it.credentialScheme.isoNamespace ?: throw IllegalStateException("Missing namespace")
            val docType = it.credentialScheme.isoDocType ?: throw IllegalStateException("Missing doc type")
            val itemsRequestsListEntries = it.requestedAttributes?.map { reqAttr ->
                SingleItemsRequest(reqAttr, false)
            } ?: listOf()
            val itemsRequestList = mapOf(namespace to ItemsRequestList(itemsRequestsListEntries))
            DocRequest(ByteStringWrapper(ItemsRequest(docType, itemsRequestList)))
        }.toTypedArray()
        val deviceRequest = DeviceRequest("1.0", docRequests)

        val encryptionParameters = EncryptionParameters(
            nonceService.provideNonce().toByteArray(),
            decryptionKeyMaterial.publicKey.toCoseKey().getOrThrow()
        )
        return IsoMdocRequest(deviceRequest, EncryptionInfo(TYPE_DCAPI, encryptionParameters)).also {
            submitRequest(it, requestOptions.state)
        }

    }

    /**
     * Performs calculation of the [at.asitplus.iso.SessionTranscript] for DC API according to ISO/IEC 18013-7
     */
    override fun createDcApiSessionTranscript(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray(
                toBeHashed as? DCAPIInfo ?: throw IllegalStateException("Expected DCAPIInfo")
            ).sha256(),
        )
    )

    private fun VerifyPresentationResult.mapToResponseResult() = when (this) {
        is VerifyPresentationResult.ValidationError -> Iso180137AnnexCResponseResult.ValidationError(cause = cause)
        is VerifyPresentationResult.Success -> Iso180137AnnexCResponseResult.Success(vp)
        is VerifyPresentationResult.SuccessIso -> Iso180137AnnexCResponseResult.SuccessIso(documents)
        is VerifyPresentationResult.SuccessSdJwt -> throw IllegalStateException("Unexpected SuccessSdJwt")
    }

    @OptIn(SecretExposure::class)
    suspend fun validateResponse(
        receivedData: DCAPIResponse,
        externalId: String,
        decryptHpke: suspend (ByteArray, ByteArray, CryptoPrivateKey.EC.WithPublicKey, ByteArray) -> ByteArray,
        expectedOrigin: String
    ): Iso180137AnnexCResponseResult {
        val isoMdocRequest = stateToIsoMdocRequestStore.get(externalId)!!
        val privateKey = decryptionKeyMaterial.exportPrivateKey().getOrThrow()
                as? CryptoPrivateKey.EC.WithPublicKey ?: throw IllegalStateException("Expected EC private key")

        val encryptedResponseData = receivedData.response.encryptedResponseData
        val serializedOrigin = expectedOrigin.serializeOrigin()
            ?: throw IllegalStateException("Expected origin invalid")

        val sessionTranscript = createDcApiSessionTranscript(
            DCAPIInfo(
                encryptionInfo = isoMdocRequest.encryptionInfo,
                serializedOrigin = serializedOrigin,
            )
        )
        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val encodedDeviceResponse = decryptHpke(encryptedResponseData.enc, encryptedResponseData.cipherText, privateKey, encodedSessionTranscript)
        val deviceResponse = coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(encodedDeviceResponse)

        return validatorMdoc.verifyDeviceResponse(
            deviceResponse,
            verifyDocumentCallback = verifyDocument(
                sessionTranscript = sessionTranscript
            )
        ).mapToResponseResult()
    }
}