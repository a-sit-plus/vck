@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import io.github.aakira.napier.Napier
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Driving privileges (7.2.4)
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class DrivingPrivilege(
    @SerialName("vehicle_category_code")
    val vehicleCategoryCode: String,
    @SerialName("issue_date")
    val issueDate: LocalDate? = null,
    @SerialName("expiry_date")
    val expiryDate: LocalDate? = null,
    @SerialName("codes")
    val codes: Array<DrivingPrivilegeCode>? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DrivingPrivilege

        if (vehicleCategoryCode != other.vehicleCategoryCode) return false
        if (issueDate != other.issueDate) return false
        if (expiryDate != other.expiryDate) return false
        if (codes != null) {
            if (other.codes == null) return false
            if (!codes.contentEquals(other.codes)) return false
        } else if (other.codes != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = vehicleCategoryCode.hashCode()
        result = 31 * result + (issueDate?.hashCode() ?: 0)
        result = 31 * result + (expiryDate?.hashCode() ?: 0)
        result = 31 * result + (codes?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<DrivingPrivilege>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

@Serializable
data class DrivingPrivilegeCode(
    @SerialName("code")
    val code: String,
    @SerialName("sign")
    val sign: String? = null,
    @SerialName("value")
    val value: String? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<DrivingPrivilegeCode>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}