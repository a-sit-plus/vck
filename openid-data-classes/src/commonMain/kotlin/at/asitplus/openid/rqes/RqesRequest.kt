package at.asitplus.openid.rqes

import at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries.CscDocumentDigest
import at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries.OAuthDocumentDigest
import at.asitplus.dif.rqes.CollectionEntries.DocumentLocation
import at.asitplus.dif.rqes.Enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignatureQualifierEnum
import at.asitplus.dif.rqes.Enums.SignedEnvelopeProperty
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.KnownOIDs.sha_256
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * TODO: Find new home (different subfolder most likely)
 * TODO: Describe vars
 *
 * In the Wallet centric model this is the request
 * coming from the Driving application to the wallet which starts
 * the process
 */
@Serializable
data class RqesRequest(

    @SerialName("response_type")
    val responseType: String,

    @SerialName("client_id")
    val clientId: String,

    @SerialName("client_id_scheme")
    val clientIdScheme: String? = null,

    /**
     * SHOULD be direct post
     */
    @SerialName("response_mode")
    val responseMode: OpenIdConstants.ResponseMode? = null,

    /**
     * MUST be present if direct post
     */
    @SerialName("response_uri")
    val responseUri: String? = null,

    @SerialName("nonce")
    val nonce: String,

    @SerialName("state")
    val state: String? = null,

    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifierEnum = SignatureQualifierEnum.EU_EIDAS_QES,

    @SerialName("documentDigests")
    val documentDigests: List<OAuthDocumentDigest>,

    @SerialName("documentLocations")
    val documentLocations: List<DocumentLocation>,

    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOid: ObjectIdentifier = Digest.SHA256.oid,

    @SerialName("clientData")
    val clientData: String?,
) {
    fun toAuthorizationDetails(): AuthorizationDetails =
        AuthorizationDetails.CSCCredential(
            credentialID = this.clientId,
            signatureQualifier = this.signatureQualifier,
            hashAlgorithmOID = this.hashAlgorithmOid,
            documentDigests = this.documentDigests,
            documentLocations = this.documentLocations,
        )

    fun getCscDocumentDigests(
        signatureFormat: SignatureFormat,
        signAlgorithm: X509SignatureAlgorithm,
        signAlgoParam: Asn1Element? = null,
        signedProps: List<JsonObject>? = null,
        conformanceLevelEnum: ConformanceLevelEnum? = ConformanceLevelEnum.ADESBB,
        signedEnvelopeProperty: SignedEnvelopeProperty? = SignedEnvelopeProperty.defaultProperty(signatureFormat)
    ): CscDocumentDigest =
        CscDocumentDigest(
            hashes = this.documentDigests.map { it.hash },
            hashAlgorithmOid = this.hashAlgorithmOid,
            signatureFormat = signatureFormat,
            conformanceLevel = conformanceLevelEnum,
            signAlgoOid = signAlgorithm.oid,
            signAlgoParams = signAlgoParam,
            signedProps = signedProps,
            signedEnvelopeProperty = signedEnvelopeProperty
        )
}
