package at.asitplus.iso

import io.github.z4kn4fein.semver.Version
import kotlin.jvm.JvmField

/** Constants of ISO/IEC DIS 18013-5:2026. */
object IsoConstants {
    /**
     * Version 1.0 of a versioned structure, e.g. of a [DeviceRequest] without `deviceRequestInfo` and `readerAuthAll`,
     * which "shall be “1.0” if deviceRequestInfo and readerAuthAll is not present" (ISO/IEC DIS 18013-5:2026, 10.2.2).
     */
    @JvmField
    val VERSION_1_0 = Version(1, 0)

    /**
     * Version 1.1 of a versioned structure, e.g. of a [DeviceRequest] with `deviceRequestInfo` or `readerAuthAll`,
     * which shall be "“1.1” if one of them is present" (ISO/IEC DIS 18013-5:2026, 10.2.2).
     */
    @JvmField
    val VERSION_1_1 = Version(1, 1)
}
