package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Specifies an url to retrieve a status list token, and an index specifying the position in the
 * status list within that status list token that holds the token status of the the referenced
 * token.
 */
@Serializable
data class StatusListInfo(
    /**
     * JOSE:
     * idx: REQUIRED. The idx (index) claim MUST specify an Integer that represents the index to
     * check for status information in the Status List for the current Referenced Token. The value
     * of idx MUST be a non-negative number, containing a value of zero or greater.
     *
     * COSE:
     * idx: REQUIRED.
     * Unsigned integer (Major Type 0) The idx (index) claim MUST specify an Integer that represents
     * the index to check for status information in the Status List for the current Referenced
     * Token. The value of idx MUST be a non-negative number, containing a value of zero or greater.
     */
    @SerialName("idx")
    val index: ULong,
    /**
     * JOSE:
     * uri: REQUIRED. The uri (URI) claim MUST specify a String value that identifies the Status
     * List or Status List Token containing the status information for the Referenced Token. The
     * value of uri MUST be a URI conforming to RFC3986.
     *
     * COSE:
     * uri: REQUIRED. Text string (Major Type 3). The uri (URI) claim MUST specify a String value
     * that identifies the Status List or Status List Token containing the status information for
     * the Referenced Token. The value of uri MUST be a URI conforming to RFC3986.
     */
    @SerialName("uri")
    override val uri: UniformResourceIdentifier,
) : RevocationListInfo()



