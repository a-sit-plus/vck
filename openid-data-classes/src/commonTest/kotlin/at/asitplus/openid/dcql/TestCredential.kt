package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.json.JsonElement

sealed interface TestCredential {
    val format: CredentialFormatEnum
    val satisfiesCryptographicHolderBinding: Boolean
    val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier>

    interface JsonCredential : TestCredential {
        val claimStructure: JsonElement
    }

    data class SdJwtCredential(
        override val claimStructure: JsonElement,
        val type: String,
        override val satisfiesCryptographicHolderBinding: Boolean = false,
        override val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier> = listOf(),
    ) : JsonCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.DC_SD_JWT
    }

    data class MdocCredential(
        val documentType: String,
        val namespaces: Map<String, Map<String, Any>>,
        override val satisfiesCryptographicHolderBinding: Boolean = false,
        override val authorityKeyIdentifiers: Collection<DCQLAuthorityKeyIdentifier> = listOf(),
    ) : TestCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.MSO_MDOC
    }
}
