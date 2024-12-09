package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

sealed class StatusListProvisioningException : Exception() {
    data object TimeNotImplementedException : StatusListProvisioningException()
    data object RequestedTimeNotSupportedException : StatusListProvisioningException()
}