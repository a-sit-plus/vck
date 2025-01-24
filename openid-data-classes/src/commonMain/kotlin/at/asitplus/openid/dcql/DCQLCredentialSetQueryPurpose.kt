package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmInline

@Serializable(with = DCQLCredentialSetQueryPurposeSerializer::class)
sealed interface DCQLCredentialSetQueryPurpose {
    @JvmInline
    value class PurposeObject(val jsonObject: JsonObject) : DCQLCredentialSetQueryPurpose

    @JvmInline
    value class PurposeString(val string: String) : DCQLCredentialSetQueryPurpose

    sealed interface PurposeNumber : DCQLCredentialSetQueryPurpose

    @JvmInline
    value class PurposeLong(val long: Long) : PurposeNumber

    @JvmInline
    value class PurposeDouble(val double: Double) : PurposeNumber
}