package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.cbor.CoseHeaderIdentifierFun

/**
 * Sets `x5chain` to the certificate chain of [clientIdScheme], e.g. for ISO mdoc reader authentication,
 * falling back to the certificate of the key material for schemes without a chain.
 */
class CoseHeaderClientIdScheme(val clientIdScheme: ClientIdScheme) : CoseHeaderIdentifierFun<KeyMaterial> {
    override suspend operator fun invoke(
        it: CoseHeader?,
        keyMaterial: KeyMaterial,
    ) = it?.copy(
        certificateChain = when (clientIdScheme) {
            is ClientIdScheme.CertificateHash -> clientIdScheme.chain.map { it.encodeToDer() }
            is ClientIdScheme.CertificateSanDns -> clientIdScheme.chain.map { it.encodeToDer() }
            else -> keyMaterial.getCertificate()?.let { listOf(it.encodeToDer()) }
        }
    )
}
