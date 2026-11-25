package at.asitplus.wallet.ios

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.validation.RelyingPartyValidator

/**
 * Swift-friendly configuration for [OpenId4VpHolder]. It sends no HTTP requests, see
 * [at.asitplus.wallet.lib.openid.OpenId4VpProtocolClient] and [HttpExchangeBridge] for those.
 */
class OpenId4VpHolderBuilder(
    val keyMaterial: KeyMaterial,
    val subjectCredentialStore: SubjectCredentialStore,
) {
    constructor() : this(EphemeralKeyWithoutCert(), InMemorySubjectCredentialStore())

    // Null means: derive the value from the current keyMaterial in build().
    /** Holds the credentials and creates the verifiable presentation, see [HolderAgentBuilder]. */
    var holder: Holder? = null
    /** Encrypts the authn response to the verifier, if this has been requested. */
    var encryptJarm: EncryptJweFun? = null
    /** Advertised in [OpenId4VpHolder.metadata] and compared against holder's requirements. */
    var supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256)
    /** Advertised as `issuer` in [OpenId4VpHolder.metadata]. */
    var clientId: String = "https://wallet.a-sit.at/"
    /** Advertised as `authorization_endpoint` in [OpenId4VpHolder.metadata]. */
    var authorizationEndpoint: String = "openid4vp:"
    /** Stores our nonce used when fetching authn requests using POST. */
    var walletNonceMapStore: MapStore<String, String> = DefaultMapStore()
    /** Source for random bytes, i.e., nonces for encrypted responses. */
    var randomSource: RandomSource = RandomSource.Secure
    /** Callback to load encryption keys for pre-registered clients. */
    var lookupJsonWebKeysForClient: (OpenId4VpHolder.JsonWebKeyLookupInput) -> JsonWebKeySet? = { null }
    /** Allowed schemes for origins received with OpenID4VP DC API requests, invoked for every request. */
    var allowedDcApiOriginSchemes: suspend () -> Set<String> = { OpenId4VpHolder.DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES }
    /** Set to accept encrypted authorization requests fetched with a POST (when RP supports that). */
    var ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null
    /** Advertised in `wallet_metadata` to encrypt authorization requests. */
    var supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet()
    /** Set to reject a plain request object fetched with POST; needs [ephemeralEncryptionKeyService]. */
    var requireEncryptedRequests: Boolean = false
    /**
     * Validates the relying party behind requests (WRPAC, WRPRC). Configure it with the anchors of the
     * WRPAC and WRPRC providers; without them, only the integrity of requests is checked.
     */
    var relyingPartyValidator: RelyingPartyValidator = RelyingPartyValidator()

    fun build(): OpenId4VpHolder = OpenId4VpHolder(
        holder = holder ?: HolderAgent(keyMaterial, subjectCredentialStore),
        encryptJarm = encryptJarm ?: EncryptJwe(),
        supportedAlgorithms = supportedAlgorithms,
        clientId = clientId,
        authorizationEndpoint = authorizationEndpoint,
        walletNonceMapStore = walletNonceMapStore,
        randomSource = randomSource,
        lookupJsonWebKeysForClient = lookupJsonWebKeysForClient,
        allowedDcApiOriginSchemes = allowedDcApiOriginSchemes,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        supportedJweEncryptionAlgorithms = supportedJweEncryptionAlgorithms,
        requireEncryptedRequests = requireEncryptedRequests,
        relyingPartyValidator = relyingPartyValidator,
    )
}
