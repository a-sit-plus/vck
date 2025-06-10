package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.ValueTags

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ClientIdToHash"))
typealias ClientIdToHash = at.asitplus.iso.ClientIdToHash

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.DeviceAuth"))
typealias DeviceAuth = at.asitplus.iso.DeviceAuth

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.DeviceKeyInfo"))
typealias DeviceKeyInfo = at.asitplus.iso.DeviceKeyInfo

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.DeviceRequest"))
typealias DeviceRequest = at.asitplus.iso.DeviceRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.DocRequest"))
typealias DocRequest = at.asitplus.iso.DocRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.EncryptionInfo"))
typealias EncryptionInfo = at.asitplus.iso.EncryptionInfo

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.EncryptionParameters"))
typealias EncryptionParameters = at.asitplus.iso.EncryptionParameters

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ItemsRequest"))
typealias ItemsRequest = at.asitplus.iso.ItemsRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ItemsRequestList"))
typealias ItemsRequestList = at.asitplus.iso.ItemsRequestList

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.KeyAuthorization"))
typealias KeyAuthorization = at.asitplus.iso.KeyAuthorization

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ResponseUriToHash"))
typealias ResponseUriToHash = at.asitplus.iso.ResponseUriToHash

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ServerItemsRequest"))
typealias ServerItemsRequest = at.asitplus.iso.ServerItemsRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ServerRequest"))
typealias ServerRequest = at.asitplus.iso.ServerRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ServerResponse"))
typealias ServerResponse = at.asitplus.iso.ServerResponse

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.SingleItemsRequest"))
typealias SingleItemsRequest = at.asitplus.iso.SingleItemsRequest

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.ValidityInfo"))
typealias ValidityInfo = at.asitplus.iso.ValidityInfo
