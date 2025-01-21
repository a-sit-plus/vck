package at.asitplus.openid.dcql

import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmInline

sealed interface DCQLCredentialClaimStructure {
    @JvmInline
    value class JsonBasedStructure(val jsonElement: JsonElement) : DCQLCredentialClaimStructure

    @JvmInline
    value class IsoMdocStructure(val namespaceClaimValueMap: Map<String, Map<String, Any?>>) :
        DCQLCredentialClaimStructure
}