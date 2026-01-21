package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.json.JsonElement

sealed interface TestCredential {
    val format: CredentialFormatEnum

    interface JsonCredential : TestCredential {
        val claimStructure: JsonElement
    }

    data class SdJwtCredential(
        override val claimStructure: JsonElement,
        val type: String,
    ) : JsonCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.DC_SD_JWT
    }

    data class MdocCredential(
        val documentType: String,
        val namespaces: Map<String, Map<String, Any>>,
    ) : TestCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.MSO_MDOC
    }

    data class JwtVcCredential(
        override val claimStructure: JsonElement,
        val types: List<String>,
    ) : JsonCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.JWT_VC
    }
}
