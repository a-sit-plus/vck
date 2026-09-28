package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.VerifierInfo
import at.asitplus.wallet.lib.agent.KeyMaterial

/** One verifier identity capable of protecting an OpenID4VP request over the Digital Credentials API. */
data class DcApiRequestSigner(
    val clientIdScheme: ClientIdScheme,
    val keyMaterial: KeyMaterial,
    /**
     * Attestations about this identity, carried in the payload of a compact signed request, and in this signer's
     * protected header of a multisigned request, see OpenID4VP 1.0, A.3.2.
     */
    val verifierInfo: NonEmptyList<VerifierInfo>? = null,
)
