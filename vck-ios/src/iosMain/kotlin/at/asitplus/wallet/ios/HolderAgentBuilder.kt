package at.asitplus.wallet.ios

import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.VerifiablePresentationFactory
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine
import kotlin.time.Clock

/** Swift-friendly configuration for [HolderAgent], as Swift can not use default arguments of Kotlin constructors. */
class HolderAgentBuilder(
    val keyMaterial: KeyMaterial,
    val subjectCredentialStore: SubjectCredentialStore,
) {
    constructor() : this(EphemeralKeyWithoutCert(), InMemorySubjectCredentialStore())

    // Used for the default verifiablePresentationFactory only.
    var signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk())
    var signKeyBinding: SignJwtFun<KeyBindingJws> = SignJwt(keyMaterial, JwsHeaderNone())
    /** Signs the session transcript for mDoc responses. */
    var signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> =
        SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone())
    var mdocZkEngine: IsoMdocZkEngine = IsoMdocZkEngine()
    /** Clock to use for timestamps in the presentations generated. */
    var clock: Clock = Clock.System

    /** Null means: build it in [build] from the signing functions above. */
    var verifiablePresentationFactory: VerifiablePresentationFactory? = null
    /**
     * Validates credentials before they are stored. Configure trust anchors per credential type;
     * without them, only integrity is checked.
     */
    var credentialValidator: CredentialValidator = CredentialValidator()
    /** Orders stored credentials when matching them; null means [credentialValidator]. */
    var orderingValidator: CredentialValidator? = null

    fun build(): HolderAgent = HolderAgent(
        keyMaterial = keyMaterial,
        subjectCredentialStore = subjectCredentialStore,
        verifiablePresentationFactory = verifiablePresentationFactory ?: VerifiablePresentationFactory(
            keyMaterial = keyMaterial,
            signVerifiablePresentation = signVerifiablePresentation,
            signKeyBinding = signKeyBinding,
            mdocZkEngine = mdocZkEngine,
            signDeviceAuthDetached = signDeviceAuthDetached,
            clock = clock,
        ),
        credentialValidator = credentialValidator,
        orderingValidator = orderingValidator ?: credentialValidator,
    )
}
