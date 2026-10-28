package at.asitplus.wallet.lib.openid

import at.asitplus.legacy.JwsHeader
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun

class JwsHeaderClientIdScheme(val clientIdScheme: ClientIdScheme) : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = when (clientIdScheme) {
        is ClientIdScheme.CertificateHash -> it.copy(certificateChain = clientIdScheme.chain)
        is ClientIdScheme.CertificateSanDns -> it.copy(certificateChain = clientIdScheme.chain)
        is ClientIdScheme.VerifierAttestation -> it.copy(
            jsonWebKey = keyMaterial.jsonWebKey,
            attestationJwt = clientIdScheme.attestationJwt.raw
        )

        else -> it.copy(jsonWebKey = keyMaterial.jsonWebKey)
    }
}