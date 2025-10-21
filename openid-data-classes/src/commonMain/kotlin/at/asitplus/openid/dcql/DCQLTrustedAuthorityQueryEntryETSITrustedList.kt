package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
@SerialName(DCQLTrustedAuthorityQueryEntryETSITrustedList.SERIAL_NAME)
data class DCQLTrustedAuthorityQueryEntryETSITrustedList(
    @SerialName(SerialNames.VALUES)
    override val values: NonEmptyList<String>,
) : DCQLTrustedAuthorityQueryEntry {
    @SerialName(SerialNames.TYPE)
    @EncodeDefault
    override val type = DCQL_TRUSTED_AUTHORITY_TYPE

    companion object {
        const val SERIAL_NAME = "etsi_tl"
        val DCQL_TRUSTED_AUTHORITY_TYPE = DCQLTrustedAuthorityType.valueOf(SERIAL_NAME)
    }

    object SerialNames {
        const val TYPE = DCQLTrustedAuthorityQueryEntry.SerialNames.TYPE
        const val VALUES = DCQLTrustedAuthorityQueryEntry.SerialNames.VALUES
    }
}

