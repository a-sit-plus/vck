package at.asitplus.wallet.lib.validation

/**
 * A credential in its encoded form, as received, together with its explicitly declared format.
 *
 * The validator decodes exactly the declared format and never infers a format from the content. Keeping the encoded
 * form lets signatures and disclosure digests be checked over the bytes that were actually received.
 */
sealed interface CredentialValidationInput {

    /** A W3C VC as JWT, in JWS compact serialization. */
    data class VcJwt(val compact: String) : CredentialValidationInput

    /** An SD-JWT VC as issued, i.e. the issuer-signed JWT followed by its disclosures, without a key binding JWT. */
    data class SdJwtVc(val compact: String) : CredentialValidationInput

    /** An ISO mdoc as the CBOR encoding of its `IssuerSigned` structure. */
    class IsoMdoc(val issuerSignedCbor: ByteArray) : CredentialValidationInput {
        override fun equals(other: Any?): Boolean =
            this === other || other is IsoMdoc && issuerSignedCbor.contentEquals(other.issuerSignedCbor)

        override fun hashCode(): Int = issuerSignedCbor.contentHashCode()

        override fun toString(): String = "IsoMdoc(issuerSignedCbor=${issuerSignedCbor.toHexString()})"
    }
}
