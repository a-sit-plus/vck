package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.openid.ClientIdScheme
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier
import at.asitplus.wallet.lib.openid.OpenIdRequestOptions
import at.asitplus.wallet.lib.openid.RequestOptions
import at.asitplus.wallet.lib.rqes.helper.OpenIdRqesParameters
import com.benasher44.uuid.uuid4
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString

/**
 * Verifier with access to [TransactionData] class can now generate requests containing [TransactionData]
 */
class RqesOpenId4VpVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(DefaultVerifierCryptoService()),
    timeLeewaySeconds: Long = 300L,
    clock: Clock = Clock.System,
    nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests, to verify the authn response to it */
    stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
) : OpenId4VpVerifier(
    clientIdScheme,
    keyMaterial,
    verifier,
    jwsService,
    verifierJwsService,
    verifierCoseService,
    timeLeewaySeconds,
    clock,
    nonceService,
    stateToAuthnRequestStore
) {
    /**
     * ExtendedRequestOptions cannot generate DifInputDescriptors!
     */
    data class ExtendedRequestOptions(
        val baseRequestOptions: OpenIdRequestOptions,
        val rqesParameters: OpenIdRqesParameters,
    ) : RequestOptions by baseRequestOptions {

        override fun toPresentationDefinition(
            containerJwt: FormatContainerJwt,
            containerSdJwt: FormatContainerSdJwt
        ): PresentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = this.toInputDescriptor(containerJwt, containerSdJwt)
        )

        override fun toInputDescriptor(
            containerJwt: FormatContainerJwt,
            containerSdJwt: FormatContainerSdJwt,
        ): List<InputDescriptor> = credentials.map { requestOptionCredential ->
            QesInputDescriptor(
                id = requestOptionCredential.buildId(),
                format = requestOptionCredential.toFormatHolder(containerJwt, containerSdJwt),
                constraints = requestOptionCredential.toConstraint(),
                transactionData = rqesParameters.transactionData.toList()
            )
        }
    }

    override suspend fun enrichAuthnRequest(
        params: AuthenticationRequestParameters,
        requestOptions: RequestOptions,
    ): AuthenticationRequestParameters = with(requestOptions) {
        when (this) {
            is OpenIdRequestOptions -> params
            is ExtendedRequestOptions -> params.copy(
                transactionData = this.rqesParameters.transactionData.map {
                    vckJsonSerializer.encodeToString(it)
                }.toSet()
            )

            else -> throw NotImplementedError("Unknown RequestOption class: ${this::class}")
        }
    }

}
