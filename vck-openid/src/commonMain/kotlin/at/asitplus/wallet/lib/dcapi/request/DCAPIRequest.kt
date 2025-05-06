package at.asitplus.wallet.lib.dcapi.request

sealed class DCAPIRequest {

    abstract fun serialize(): String
}