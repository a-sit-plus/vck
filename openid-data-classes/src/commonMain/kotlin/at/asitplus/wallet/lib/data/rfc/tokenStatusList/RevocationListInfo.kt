package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier

/**
 * Marker type for a token status mechanism.
 * Carries only the URI plus flavor-specific metadata so the resolver can download and
 * interpret the right [RevocationList].
 */
sealed class RevocationListInfo {
    abstract val uri: UniformResourceIdentifier

    /**
     * The identifier_list and status_list in the MSO may contain the Certificate element. If the
     * Certificate element is present, it shall contain a certificate containing the public key that signed the
     * top-level certificate in the x5chain element in the MSO revocation list structure. The mdoc reader shall
     * use that certificate as trust point for verification of the x5chain element in the MSO revocation list
     * structure. If the Certificate element is not present, the top-level certificate in the x5chain element
     * shall be signed by the certificate used to sign the certificate in the x5chain element of the MSO. In the
     * context of an mDL, that is the IACA certificate.
     */
    abstract val certificate: ByteArray?
}
