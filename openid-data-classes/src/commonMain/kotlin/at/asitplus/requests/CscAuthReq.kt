package at.asitplus.requests

import at.asitplus.openid.Hashes
import at.asitplus.openid.HashesSerializer
import at.asitplus.openid.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.JsonWebToken
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

sealed interface CscAuthReq : AuthenticationRequest{
    /**
     * CSC: Optional
     * Request a preferred language according to RFC 5646
     */
    @SerialName("lang")
    val lang: String?

    /**
     * CSC: REQUIRED-"credential"
     * The identifier associated to the credential to authorize.
     * This parameter value may contain characters that are reserved, unsafe or
     * forbidden in URLs and therefore SHALL be url-encoded by the signature
     * application
     */
    @SerialName("credentialID")
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val credentialID: ByteArray?

    /**
     * CSC: Required-"credential"
     * This parameter contains the symbolic identifier determining the kind of
     * signature to be created
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier?

    /**
     * CSC: Required-"credential"
     * The number of signatures to authorize
     */
    @SerialName("numSignatures")
    val numSignatures: Int?

    /**
     * CSC: REQUIRED-"credential"
     * One or more base64url-encoded hash values to be signed
     */
    @SerialName("hashes")
    @Serializable(HashesSerializer::class)
    val hashes: Hashes?

    /**
     * CSC: REQUIRED-"credential"
     * String containing the OID of the hash algorithm used to generate the hashes
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier?

    /**
     * CSC: OPTIONAL
     * A free form description of the authorization transaction in the lang language.
     * The maximum size of the string is 500 characters
     */
    @SerialName("description")
    val description: String?

    /**
     * CSC: OPTIONAL
     * To restrict access to the authorization server of a remote service, this specification introduces the
     * additional account_token parameter to be used when calling the oauth2/authorize endpoint. This
     * parameter contains a secure token designed to authenticate the authorization request based on an
     * Account ID that SHALL be uniquely assigned by the signature application to the signing user or to the
     * user’s application account
     */
    @SerialName("account_token")
    val accountToken: JsonWebToken?

    /**
     * CSC: OPTIONAL
     * Arbitrary data from the signature application. It can be used to handle a
     * transaction identifier or other application-specific data that may be useful for
     * debugging purposes
     */
    @SerialName("clientData")
    val clientData: String?
}