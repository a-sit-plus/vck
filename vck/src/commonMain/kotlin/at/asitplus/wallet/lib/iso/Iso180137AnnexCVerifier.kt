package at.asitplus.wallet.lib.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
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
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.extensions.sessionTranscriptThumbprint
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

    //val verifier: Verifier = VerifierAgent(identifier = "I don't care, I only need IsoMdoc"),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(),
) : AbstractMdocVerifier() {

    /**
     * Remembers [authenticationRequestParameters] to link responses to requests in [validateAuthnResponse].
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
                SingleItemsRequest(reqAttr, false) // TODO find out what value is. intentToRetain maybe? or required?
            } ?: listOf()
            val itemsRequestList = mapOf(namespace to ItemsRequestList(itemsRequestsListEntries))
            DocRequest(ByteStringWrapper(ItemsRequest(docType, itemsRequestList)))
        }.toTypedArray()
        val deviceRequest = DeviceRequest("1.0", docRequests) //TODO find out correct version

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
        nonce: String,
        hasBeenEncrypted: Boolean,
        origin: String,
    ): SessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = DCAPIHandover.TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray<OpenID4VPDCAPIHandoverInfo>(
                OpenID4VPDCAPIHandoverInfo(
                    origin = origin,
                    nonce = nonce,
                    jwkThumbprint = if (hasBeenEncrypted) {
                        decryptionKeyMaterial.jsonWebKey.sessionTranscriptThumbprint()
                    } else null,
                )
            ).sha256(),
        )
    )

    @OptIn(SecretExposure::class)
    suspend fun validateResponse(
        receivedData: DCAPIResponse,
        externalId: String,
        decryptHpke: suspend (ByteArray, ByteArray, CryptoPrivateKey.EC.WithPublicKey, ByteArray) -> ByteArray,
        expectedOrigin: String
    ): ResponseResult {
        println("Parsed response successfully = ${receivedData.response.type}")
        val isoMdocRequest = stateToIsoMdocRequestStore.get(externalId)!!
        val privateKey = decryptionKeyMaterial.exportPrivateKey().getOrThrow()
                as? CryptoPrivateKey.EC.WithPublicKey ?: throw IllegalStateException("Expected EC private key")

        println("privateKey = ${privateKey}")
        val encryptedResponseData = receivedData.response.encryptedResponseData
        val serializedOrigin = expectedOrigin.serializeOrigin()
            ?: throw IllegalStateException("Expected origin invalid")

        //TODO use createDcApiSessionTranscript() function

        val dcapiInfo = DCAPIInfo(isoMdocRequest.encryptionInfo, serializedOrigin)
        val hash = coseCompliantSerializer.encodeToByteArray(dcapiInfo).sha256() // TODO can we do this with serialization? Would probably need CborClassDiscriminator though
        val sessionTranscript = SessionTranscript.forDcApi(DCAPIHandover("dcapi", hash))
        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val encodedDeviceResponse = decryptHpke(encryptedResponseData.enc, encryptedResponseData.cipherText, privateKey, encodedSessionTranscript)
        val deviceResponse = coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(encodedDeviceResponse)
        println("deviceResponse = ${deviceResponse}")

        val result = validatorMdoc.verifyDeviceResponse(
            deviceResponse,
            verifyDocumentCallback = verifyDocument(
                sessionTranscript = sessionTranscript
            )
        )
        println("result = ${result}")
        TODO("return result")
    }
}