package at.asitplus.wallet.ios

import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.internals.toNSData
import platform.Foundation.NSData

/** Uses Signum's bulk-copy conversions rather than per-byte Objective-C calls. */
object ByteArrayBridge {
    @Throws(IndexOutOfBoundsException::class)
    fun fromData(data: NSData): ByteArray = data.toByteArray()
    fun toData(bytes: ByteArray): NSData = bytes.toNSData()
}
