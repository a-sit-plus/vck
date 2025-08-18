package at.asitplus.requests

import kotlinx.serialization.Serializable

//Generic concept Authentication Request
@Serializable(with = AuthenticationRequestSerializer::class)
sealed interface AuthenticationRequest : RequestParameters