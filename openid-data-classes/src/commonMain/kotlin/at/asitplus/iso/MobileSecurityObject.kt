package at.asitplus.iso

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import io.github.z4kn4fein.semver.Version
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class MobileSecurityObject(
    @SerialName("version")
    @Serializable(with = IsoVersionSerializer::class)
    val parsedVersion: Version,
    @SerialName("digestAlgorithm")
    @Serializable(with = IsoDigestSerializer::class)
    val digest: Digest,
    @SerialName("valueDigests")
    val valueDigests: Map<String, ValueDigestList>,
    @SerialName("deviceKeyInfo")
    val deviceKeyInfo: DeviceKeyInfo,
    @SerialName("docType")
    val docType: String,
    @SerialName("validityInfo")
    val validityInfo: ValidityInfo,
    @SerialName("status")
    @Serializable(with = RevocationListInfo.StatusSurrogateSerializer::class)
    val status: RevocationListInfo? = null,
)
