package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.equalsCryptographically

/** Finds the [KeyMaterial] of the key a credential is bound to, so a holder can use a different key per credential. */
fun interface HolderKeyResolver {
    /** The key material of [boundKey]; fails e.g. for an unknown key or a keystore error. */
    suspend fun resolve(boundKey: CryptoPublicKey): KmmResult<KeyMaterial>

    companion object {
        /** Resolves only [key], for a holder with a single key. */
        fun single(key: KeyMaterial) = HolderKeyResolver { boundKey ->
            catching {
                require(boundKey.equalsCryptographically(key.publicKey)) { "Unknown holder key" }
                key
            }
        }
    }
}
