package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
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
import com.benasher44.uuid.uuid4
import io.ktor.util.*
import kotlinx.datetime.Clock

/**
 * Verifier with access to [TransactionData] class can now generate requests containing [TransactionData]
 */
@Deprecated("OpenId4VpVerifier can now access TransactionData, for RqesRequests use RqesRequestOptions", ReplaceWith("OpenId4VpVerifier"))
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
     * Necessary to use [QesInputDescriptor]
     * ExtendedRequestOptions cannot generate [DifInputDescriptor]!
     */
    @Deprecated("Replaced", ReplaceWith("RqesRequestOptions"))
    data class ExtendedRequestOptions(
        val baseRequestOptions: OpenIdRequestOptions,
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
                transactionData = transactionData?.toList()
            )
        }
    }
}
