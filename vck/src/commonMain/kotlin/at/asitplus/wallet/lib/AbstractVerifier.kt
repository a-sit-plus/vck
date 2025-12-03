package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial

interface AbstractVerifier {
    /** Creates challenges in authentication requests. */
    abstract val nonceService: NonceService
    /** Used for encrypted responses. */
    abstract val decryptionKeyMaterial: KeyMaterial



}