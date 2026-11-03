package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C supervisory-authority contact block. Each field is absent if the register provides
 * no value for it, and always encoded as an array, see [WrpStringListSerializer].
 */
@Serializable
data class WrpSupervisoryAuthority(
    /** Email addresses of the competent data protection authority (Table 7; email `[0..*]`, clause B.2.2). */
    @SerialName("email")
    @Serializable(with = WrpStringListSerializer::class)
    val emails: List<String>? = null,

    /** Telephone numbers of the competent data protection authority (Table 7; phone `[0..*]`, clause B.2.2). */
    @SerialName("phone")
    @Serializable(with = WrpStringListSerializer::class)
    val phones: List<String>? = null,

    /**
     * URLs of the web form provided by the competent data protection authority (Table 7; infoURI `[0..*]`,
     * clause B.2.2).
     */
    @SerialName("uri")
    @Serializable(with = WrpStringListSerializer::class)
    val uris: List<String>? = null,
) {
    init {
        require(emails?.isNotEmpty() != false) { "email must not be empty" } // B.2.2: [0..*], absent if none
        require(phones?.isNotEmpty() != false) { "phone must not be empty" } // B.2.2: [0..*], absent if none
        require(uris?.isNotEmpty() != false) { "uri must not be empty" } // B.2.2: [0..*], absent if none
    }

    @Deprecated("Several email addresses may be registered", ReplaceWith("emails?.first()"))
    val email: String?
        get() = emails?.first()

    @Deprecated("Several telephone numbers may be registered", ReplaceWith("phones?.first()"))
    val phone: String?
        get() = phones?.first()

    @Deprecated("Several web form URLs may be registered", ReplaceWith("uris?.first()"))
    val uri: String?
        get() = uris?.first()
}
