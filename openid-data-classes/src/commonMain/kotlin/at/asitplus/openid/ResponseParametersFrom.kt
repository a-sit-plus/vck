package at.asitplus.openid

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Intermediate class to transport the source of parsed [AuthenticationResponseParameters]
 */
sealed class ResponseParametersFrom {

    abstract val parameters: AuthenticationResponseParameters
    open val clientIdRequired: Boolean = true
    abstract val hasBeenEncrypted: Boolean

    data class JwsSigned(
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<AuthenticationResponseParameters>,
        val parent: ResponseParametersFrom,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom() {
        override val hasBeenEncrypted: Boolean = false
    }

    data class JweDecrypted(
        val jweDecrypted: at.asitplus.signum.indispensable.josef.JweDecrypted<AuthenticationResponseParameters>,
        val parent: ResponseParametersFrom,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom() {
        override val hasBeenEncrypted: Boolean = true
    }

    data class Uri(
        val url: Url,
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom() {
        override val hasBeenEncrypted: Boolean = false
    }

    data class Post(
        override val parameters: AuthenticationResponseParameters,
    ) : ResponseParametersFrom() {
        override val hasBeenEncrypted: Boolean = false
    }

    @Serializable
    data class DcApi(
        /** Format `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
        @SerialName("protocol")
        val protocol: ExchangeProtocolIdentifier,
        @SerialName("data")
        override val parameters: AuthenticationResponseParameters,
        @SerialName("origin")
        val origin: String,
    ): ResponseParametersFrom() {
        override val clientIdRequired get() = run { !protocol.isUnsignedOpenId4VpRequest }
        override val hasBeenEncrypted: Boolean = false
    }

}


