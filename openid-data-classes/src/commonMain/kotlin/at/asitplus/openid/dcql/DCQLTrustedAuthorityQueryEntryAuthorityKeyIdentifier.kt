package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
@SerialName(DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier.SERIAL_NAME)
data class DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
    @SerialName(SerialNames.VALUES)
    override val values: NonEmptyList<String>,
) : DCQLTrustedAuthorityQueryEntry {
    @SerialName(SerialNames.TYPE)
    @EncodeDefault
    override val type = DCQL_TRUSTED_AUTHORITY_TYPE

    @Transient
    val authorityKeyIdentifiers = values.map {
        DCQLAuthorityKeyIdentifier(it)
    }.toNonEmptyList()

    companion object {
        const val SERIAL_NAME = "aki"
        val DCQL_TRUSTED_AUTHORITY_TYPE = DCQLTrustedAuthorityType.valueOf(SERIAL_NAME)
    }

    object SerialNames {
        const val TYPE = DCQLTrustedAuthorityQueryEntry.SerialNames.TYPE
        const val VALUES = DCQLTrustedAuthorityQueryEntry.SerialNames.VALUES
    }
}

