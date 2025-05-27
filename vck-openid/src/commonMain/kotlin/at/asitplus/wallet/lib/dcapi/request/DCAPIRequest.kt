package at.asitplus.wallet.lib.dcapi.request

/*
 * Sealed abstract base class for requests received via the Digital Credentials API.
 */
sealed class DCAPIRequest {
    abstract fun serialize(): String
}