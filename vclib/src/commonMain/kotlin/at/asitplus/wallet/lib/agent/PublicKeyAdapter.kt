package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.CryptoPublicKey

/**
 * Notes for later:
 * - Issuer needs to select one key somehow ... identifier must match the one that signs it too
 * - Holder can have a list of public keys, and we need to check against each of those, one has to match
 */

interface PublicKeyAdapter {
    // TODO make this a list? i.e. when more than one holder key can be used
    val publicKey: CryptoPublicKey
    //val publicKeys: Collection<CryptoPublicKey>
    // TODO make this a list? see above
    val identifier: String
}

class InMemoryPublicKeyAdapter(
    override val publicKey: CryptoPublicKey
) : PublicKeyAdapter {
    override val identifier: String = publicKey.didEncoded
}