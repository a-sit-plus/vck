package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex B MultiLangString (clause B.2.6), as used by registrars, in contrast to
 * [WrpLangString] of registration certificates.
 */
@Serializable
data class WrpMultiLangString(
    /** Alpha-2 language code according to ISO 639 (Set 1). */
    @SerialName("lang")
    val lang: String,

    /** The localized text. */
    @SerialName("content")
    val content: String,
)
