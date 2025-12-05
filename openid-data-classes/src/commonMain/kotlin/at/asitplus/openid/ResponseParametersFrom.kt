package at.asitplus.openid

import at.asitplus.dcapi.OpenId4VpResponse
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

    @ConsistentCopyVisibility
    data class DcApi private constructor(
        override val parameters: AuthenticationResponseParameters,
        val origin: String,
        override val clientIdRequired: Boolean,
        override val hasBeenEncrypted: Boolean,
    ) : ResponseParametersFrom() {
        companion object {
            fun createFromOpenId4VpResponse(input: OpenId4VpResponse): DcApi {
                return DcApi(
                    parameters = input.data,
                    origin = input.origin,
                    clientIdRequired = !input.protocol.isUnsignedOpenId4VpRequest,
                    hasBeenEncrypted = input.data.issuer != null // TODO is there a better way to detect this?
                )
            }
        }
    }

}


