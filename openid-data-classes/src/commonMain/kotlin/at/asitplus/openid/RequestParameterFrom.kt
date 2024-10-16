package at.asitplus.openid

import kotlinx.serialization.Serializable

@Serializable
sealed interface RequestParametersFrom {
    @Serializable(with  = RequestParametersSerializer::class)
    val parameters: RequestParameters
}