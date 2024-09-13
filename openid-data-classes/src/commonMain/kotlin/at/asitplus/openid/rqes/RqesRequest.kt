package at.asitplus.openid.rqes

import at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries.OAuthDocumentDigest
import at.asitplus.dif.rqes.CollectionEntries.DocumentLocation
import at.asitplus.dif.rqes.Enums.SignatureQualifier
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.Serializable

/**
 * TODO: Find new home (different subfolder most likely)
 *
 * In the Wallet centric model this is the request
 * coming from the Driving application to the wallet which starts
 * the process
 */
@Serializable
data class RqesRequest(
    val responseType: String,
    val clientId: String,
    val clientIdScheme: String? = null,

    /**
     * SHOULD be direct post
     */
    val responseMode: OpenIdConstants.ResponseMode? = null,

    /**
     * MUST be present if direct post
     */
    val responseUri: String? = null,
    val nonce: String,
    val state: String? = null,
    val signatureQualifier: SignatureQualifier = SignatureQualifier.EU_EIDAS_QES,
    val documentDigests: List<OAuthDocumentDigest>,
    val documentLocations: List<DocumentLocation>,
    val hashAlgorithmOid: ObjectIdentifier,
    val clientData: String,
)
