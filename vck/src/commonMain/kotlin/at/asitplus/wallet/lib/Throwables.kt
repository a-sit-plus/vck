package at.asitplus.wallet.lib

sealed class VcLibException(message: String, cause: Throwable? = null) : Throwable(message, cause)

class DataSourceProblem(message: String, val details: String? = null, cause: Throwable? = null) :
    VcLibException(message, cause)

class AuthenticationError(message: String, cause: Throwable? = null) : VcLibException(message, cause)

