package at.asitplus.rqes

import CscAuthorizationDetails
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.rqes.collection_entries.CscDocumentDigest
import at.asitplus.rqes.collection_entries.DocumentLocation
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.ConformanceLevelEnum
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.enums.SignatureQualifierEnum
import at.asitplus.rqes.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject

/**
 * In the Wallet centric model this is the request
 * coming from the Driving application to the wallet which starts
 * the process
 *
 * This should not be confused with the CSC-related extensions to [AuthenticationRequestParameters] which are used
 * by the wallet to communicate with the QTSP using OAuth2
 */
@Serializable
data class SignatureRequestParameters(

    /**
     * OIDC: REQUIRED. OAuth 2.0 Response Type value that determines the authorization processing flow to be used,
     * including what parameters are returned from the endpoints used. When using the Authorization Code Flow, this
     * value is `code`.
     *
     * For OIDC SIOPv2, this is typically `id_token`. For OID4VP, this is typically `vp_token`.
     *
     * Optional when JAR (RFC9101) is used.
     */
    @SerialName("response_type")
    val responseType: String,

    /**
     * OIDC: REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     */
    @SerialName("client_id")
    val clientId: String,

    /**
     * OID4VP: OPTIONAL. A string identifying the scheme of the value in the `client_id` Authorization Request parameter
     * (Client Identifier scheme). The [clientIdScheme] parameter namespaces the respective Client Identifier. If an
     * Authorization Request uses the [clientIdScheme] parameter, the Wallet MUST interpret the Client Identifier of
     * the Verifier in the context of the Client Identifier scheme. If the parameter is not present, the Wallet MUST
     * behave as specified in RFC6749. If the same Client Identifier is used with different Client Identifier schemes,
     * those occurrences MUST be treated as different Verifiers. Note that the Verifier needs to determine which Client
     * Identifier schemes the Wallet supports prior to sending the Authorization Request in order to choose a supported
     * scheme.
     */
    @SerialName("client_id_scheme")
    val clientIdScheme: OpenIdConstants.ClientIdScheme? = null,

    /**
     * OAuth 2.0 Responses: OPTIONAL. Informs the Authorization Server of the mechanism to be used for returning
     * Authorization Response parameters from the Authorization Endpoint. This use of this parameter is NOT RECOMMENDED
     * with a value that specifies the same Response Mode as the default Response Mode for the Response Type used.
     * SHOULD be direct post
     */
    @SerialName("response_mode")
    val responseMode: OpenIdConstants.ResponseMode? = null,

    /**
     * OID4VP: OPTIONAL. The Response URI to which the Wallet MUST send the Authorization Response using an HTTPS POST
     * request as defined by the Response Mode `direct_post`. The Response URI receives all Authorization Response
     * parameters as defined by the respective Response Type. When the `response_uri` parameter is present,
     * the `redirect_uri` Authorization Request parameter MUST NOT be present. If the `redirect_uri` Authorization
     * Request parameter is present when the Response Mode is `direct_post`, the Wallet MUST return an
     * `invalid_request` Authorization Response error.
     */
    @SerialName("response_uri")
    val responseUrl: String? = null,

    /**
     * OIDC: OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
     * The value is passed through unmodified from the Authentication Request to the ID Token. Sufficient entropy MUST
     * be present in the nonce values used to prevent attackers from guessing values.
     */
    @SerialName("nonce")
    val nonce: String,

    /**
     * OIDC: RECOMMENDED. Opaque value used to maintain state between the request and the callback. Typically,
     * Cross-Site Request Forgery (CSRF, XSRF) mitigation is done by cryptographically binding the value of this
     * parameter with a browser cookie.
     */
    @SerialName("state")
    val state: String? = null,

    /**
     * UC5 Draft REQUIRED.
     * This parameter contains the symbolic identifier determining the kind of
     * signature to be created
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifierEnum = SignatureQualifierEnum.EU_EIDAS_QES,

    /**
     * UC5 Draft REQUIRED.
     * An array composed of entries for every
     * document to be signed
     */
    @SerialName("documentDigests")
    val documentDigests: List<OAuthDocumentDigest>,

    /**
     * UC5 Draft REQUIRED.
     * An array composed of entries for every
     * document to be signed
     */
    @SerialName("documentLocations")
    val documentLocations: List<DocumentLocation>,

    /**
     * UC5 Draft REQUIRED.
     * String containing the OID of the hash
     * algorithm used to generate the hashes listed
     * in [documentDigests]
     */
    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOid: ObjectIdentifier = Digest.SHA256.oid,

    /**
     * CSC: OPTIONAL
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-spe cific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String?,
) : RequestParameters {

    @Transient
    val hashAlgorithm: Digest = getHashAlgorithm(hashAlgorithmOid)

    fun toAuthorizationDetails(): AuthorizationDetails =
        CscAuthorizationDetails(
            credentialID = this.clientId,
            signatureQualifier = this.signatureQualifier,
            hashAlgorithmOid = this.hashAlgorithmOid,
            documentDigests = this.documentDigests,
            documentLocations = this.documentLocations,
        )

    fun getCscDocumentDigests(
        signatureFormat: SignatureFormat,
        signAlgorithm: X509SignatureAlgorithm,
        signAlgoParam: Asn1Element? = null,
        signedProps: List<JsonObject>? = null,
        conformanceLevelEnum: ConformanceLevelEnum? = ConformanceLevelEnum.ADESBB,
        signedEnvelopeProperty: SignedEnvelopeProperty? = SignedEnvelopeProperty.defaultProperty(signatureFormat),
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
