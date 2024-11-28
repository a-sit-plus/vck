package at.asitplus.wallet.lib.data.rfc9596.cose.headers

import at.asitplus.wallet.lib.data.rfc8392.cose.CoseHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * specification: https://www.rfc-editor.org/rfc/rfc9596
 *
 *  2. COSE "typ" (type) Header Parameter
 *
 * The "typ" (type) header parameter is used by COSE applications to declare
 * the type of this complete COSE object, as compared to the content type header
 * parameter, which declares the type of the COSE object payload. This is intended
 * for use by the application when more than one kind of COSE object could be
 * present in an application data structure that can contain a COSE object; the
 * application can use this value to disambiguate among the different kinds of
 * COSE objects that might be present. It will typically not be used by applications
 * when the kind of COSE object is already known. Use of this header parameter is OPTIONAL.
 *
 * The syntax of this header parameter value is the same as the content type header
 * parameter defined in Section 3.1 of [RFC9052]; it is either an unsigned integer
 * as registered in the "CoAP Content-Formats" registry [CoAP.ContentFormats] or a
 * string content type value. Content type values have a media type name [MediaTypes]
 * and MAY include media type parameters. The "typ" (type) header parameter is ignored
 * by COSE implementations (libraries implementing [RFC9052] and this specification),
 * other than being passed through to applications using those implementations.
 * Any processing of this parameter is performed by the COSE application using
 * application-specific processing rules. For instance, an application might verify
 * that the "typ" value is a particular application-chosen media type and reject the
 * data structure if it is not.
 *
 * The "typ" parameter MUST NOT be present in unprotected headers.
 * The "typ" parameter does not describe the content of unprotected headers.
 * Changes to unprotected headers do not change the type of the COSE object.
 */
object CoseTypeHeaderParameterSpecification : CoseHeaderParameterSpecification {
    const val NAME = "typ"
    const val KEY = 16L

    override val cborLabel: CwtClaimKey
        get() = CwtClaimKey(KEY)
    override val cborName: CwtClaimName
        get() = CwtClaimName(NAME)

    interface ParameterProvider {
        /**
         * Annotations need to be applied on derived classes.
         */
        @CborLabel(KEY)
        @SerialName(NAME)
        val typ: String?
    }

    val CoseHeaderParameterSpecification.Companion.typ: CoseTypeHeaderParameterSpecification
        get() = CoseTypeHeaderParameterSpecification
}