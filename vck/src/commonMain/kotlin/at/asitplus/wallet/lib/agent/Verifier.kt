package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.toJsonWebKey


/**
 * Verifies that [input] is a valid identifier for this key (that is not forgeable like a simple ID)
 */
fun CryptoPublicKey.matchesIdentifier(input: String): Boolean {
    if (didEncoded == input)
        return true
    with(toJsonWebKey()) {
        if (jwkThumbprint == input)
            return true
        if (didEncoded == input)
            return true
    }
    return false
}
