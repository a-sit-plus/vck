package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SupportedCredentialFormat(
    @SerialName("format")
    val format: CredentialFormatEnum,

    @SerialName("id")
    val id: String? = null,

    /**
     * e.g. `VerifiableCredential`, `UniversityDegreeCredential`
     */
    @SerialName("types")
    val types: Array<String>,

    @SerialName("credentialSubject")
    val credentialSubject: Map<String, CredentialSubjectMetadataSingle>,

    /**
     * e.g. `did`
     */
    @SerialName("cryptographic_binding_methods_supported")
    val supportedBindingMethods: Array<String>,

    /**
     * e.g. `ES256K`
     */
    @SerialName("cryptographic_suites_supported")
    val supportedCryptographicSuites: Array<String>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SupportedCredentialFormat

        if (format != other.format) return false
        if (id != other.id) return false
        if (!types.contentEquals(other.types)) return false
        if (credentialSubject != other.credentialSubject) return false
        if (!supportedBindingMethods.contentEquals(other.supportedBindingMethods)) return false
        return supportedCryptographicSuites.contentEquals(other.supportedCryptographicSuites)
    }

    override fun hashCode(): Int {
        var result = format.hashCode()
        result = 31 * result + (id?.hashCode() ?: 0)
        result = 31 * result + types.contentHashCode()
        result = 31 * result + credentialSubject.hashCode()
        result = 31 * result + supportedBindingMethods.contentHashCode()
        result = 31 * result + supportedCryptographicSuites.contentHashCode()
        return result
    }
}