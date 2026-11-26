@file:OptIn(kotlin.experimental.ExperimentalObjCName::class)

package at.asitplus.wallet.ios

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.WalletEncryptionService
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import kotlin.time.Clock

/** Kotlin defaults that Swift cannot construct directly. */
@ObjCName(swiftName = "OpenId4VciClientDefaultsBridge")
object OpenId4VciClientDefaults {
    /** A fresh ephemeral key, e.g. for a `JwtProofCreator`. */
    val keyMaterial: KeyMaterial get() = EphemeralKeyWithoutCert()
    /** Fresh encryption state for each client, as in the constructor of `OpenId4VciClient`. */
    val encryptionService: WalletEncryptionService get() = WalletEncryptionService()
    /** Embeds the key as `jwk`, as in the constructor of `JwtProofCreator`. */
    val selectProofJwtKeyBinding: suspend (KeyMaterial) -> Pair<JsonWebKey?, String?> = {
        Pair(it.jsonWebKey, null)
    }
}

/**
 * Defaults of `OAuth2Client`, `OAuth2ProtocolClient` and `OpenId4VciProtocolClient`, fresh on each access as in their
 * constructors, since they hold the state of one flow.
 */
@ObjCName(swiftName = "OpenId4VciProtocolClientDefaultsBridge")
object OpenId4VciProtocolClientDefaults {
    val stateToCodeStore: MapStore<String, String> get() = DefaultMapStore()
    val signPushedAuthorizationRequest: SignJwtFun<AuthenticationRequestParameters>
        get() = SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk())
    val dpopKeyMaterial: KeyMaterial get() = EphemeralKeyWithoutCert()
    val issuerMetadataValidator: IssuerMetadataValidator get() = IssuerMetadataValidator()
}

/** Exposes the standard system clock through its exported interface. */
@ObjCName(swiftName = "ClockAdapterBridge")
object ClockAdapter {
    val system: Clock get() = Clock.System
}
