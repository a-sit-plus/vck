package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.CryptoPublicKey

interface PublicKeyAdapter {
    // TODO make this a list? i.e. when more than one holder key can be used
    val publicKey: CryptoPublicKey
    // TODO make this a list? see above
    val identifier: String
}

class InMemoryPublicKeyAdapter(
    override val publicKey: CryptoPublicKey
) : PublicKeyAdapter {
    override val identifier: String = publicKey.didEncoded
}