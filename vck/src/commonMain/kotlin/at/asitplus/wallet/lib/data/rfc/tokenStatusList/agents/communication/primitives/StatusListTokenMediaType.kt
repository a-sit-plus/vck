package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes

enum class StatusListTokenMediaType {
    Jwt, Cwt;

    val value: String
        get() = when(this) {
            Jwt -> MediaTypes.jwtStatusList
            Cwt -> MediaTypes.cwtStatusList
        }

    companion object {
        fun valueOf(mediaType: MediaType): StatusListTokenMediaType {
            return entries.first {
                it.value == mediaType.value
            }
        }
    }
}