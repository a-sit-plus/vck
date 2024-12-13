package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.rqes.RqesInputDescriptor
import at.asitplus.rqes.collection_entries.RqesTransactionData
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import io.ktor.util.reflect.*
import kotlinx.datetime.Clock

/**
 * Verifier with access to [RqesTransactionData] class can now generate requests containing [TransactionData]
 */
class RqesOidcVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    timeLeewaySeconds: Long = 300L,
    clock: Clock = Clock.System,
    nonceService: NonceService = DefaultNonceService(),
    /**
     * Used to store the nonce, associated to the state, to first send [AuthenticationRequestParameters.nonce],
     * and then verify the challenge in the submitted verifiable presentation in
     * [AuthenticationResponseParameters.vpToken].
     */
    stateToNonceStore: MapStore<String, String> = DefaultMapStore(),
    stateToResponseTypeStore: MapStore<String, String> = DefaultMapStore(),
) : OidcSiopVerifier(
    clientIdScheme,
    keyMaterial,
    verifier,
    jwsService,
    verifierJwsService,
    timeLeewaySeconds,
    clock,
    nonceService,
    stateToNonceStore,
    stateToResponseTypeStore,
) {
    override fun RequestOptionsCredential.toInputDescriptor(): RqesInputDescriptor {
        require(this.transactionData?.all { it.instanceOf(RqesTransactionData::class) } ?: true)
        return RqesInputDescriptor(
            id = buildId(),
            format = toFormatHolder(),
            constraints = toConstraint(),
            transactionData = transactionData as List<RqesTransactionData>
        )
    }
}