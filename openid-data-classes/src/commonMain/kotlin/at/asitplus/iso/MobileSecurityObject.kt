package at.asitplus.iso

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import io.github.z4kn4fein.semver.Version
import io.github.z4kn4fein.semver.toVersion
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
    val status: TokenStatusInfo? = null,
) {
    @Deprecated("Use constructor with parsedVersion")
    constructor(
        version: String,
        digestAlgorithm: String,
        valueDigests: Map<String, ValueDigestList>,
        deviceKeyInfo: DeviceKeyInfo,
        docType: String,
        validityInfo: ValidityInfo,
        status: RevocationListInfo? = null,
    ): this(
        parsedVersion = version.toVersion(strict = false),
        digest = digestAlgorithm.toDigest(),
        valueDigests = valueDigests,
        deviceKeyInfo = deviceKeyInfo,
        docType = docType,
        validityInfo = validityInfo,
        status = status?.let(TokenStatusInfo::from)
    )

    @Deprecated("Use digest instead", ReplaceWith("digest.toIsoString()"))
    val digestAlgorithm: String
        get() = digest.toIsoString()

    @Deprecated("Use parsedVersion instead", ReplaceWith("parsedVersion.toIsoString()"))
    val version: String
        get() = parsedVersion.toIsoString()


}
