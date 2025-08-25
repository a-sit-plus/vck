package at.asitplus.openid

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Any set of parameters that might need complex parsing. See [at.asitplus.wallet.lib.openid.RequestParser]
 * Uses open serialization in order to avoid type-discriminator in serialization
 */
@JsonClassDiscriminator("")
@Serializable(with = RequestParametersSerializer::class)
sealed class RequestParameters



