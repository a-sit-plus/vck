package at.asitplus.wallet.lib.iso

import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.wallet.lib.AbstractVerifier
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.ktor.utils.io.core.toByteArray

class Iso180137AnnexCVerifier(
    /** Creates challenges in authentication requests. */
    override val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued requests to verify the response to it */
    private val stateToIsoMdocRequestStore: MapStore<String, IsoMdocRequest> = DefaultMapStore(), //stateToRequestStore

    override val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
) : AbstractVerifier {

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
    )

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

    fun validateResponse(response: DCAPIResponse, externalId: String): ResponseResult {
        println("Parsed response successfully = ${response.response.type}")
        TODO("Not yet implemented")
    }
}