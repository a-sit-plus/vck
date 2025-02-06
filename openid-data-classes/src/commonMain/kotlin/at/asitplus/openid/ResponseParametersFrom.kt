package at.asitplus.openid

import io.ktor.http.*

/**
 * Intermediate class to transport the source of parsed [AuthenticationResponseParameters]
 */
sealed class ResponseParametersFrom {

    abstract val parameters: AuthenticationResponseParameters

    data class JwsSigned(
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<AuthenticationResponseParameters>,
        val parent: ResponseParametersFrom,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom()

    data class JweForJws(
        val jweDecrypted: at.asitplus.signum.indispensable.josef.JweDecrypted<String>,
        val parent: ResponseParametersFrom,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom()

    data class JweDecrypted(
        val jweDecrypted: at.asitplus.signum.indispensable.josef.JweDecrypted<AuthenticationResponseParameters>,
        val parent: ResponseParametersFrom,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom()

    data class Uri(
        val url: Url,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom()

    data class Post(
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom()

}


