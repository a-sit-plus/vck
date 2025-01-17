package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmInline

@Serializable(with = DCQLCredentialSetQueryPurposeSerializer::class)
sealed interface DCQLCredentialSetQueryPurpose {
    @JvmInline
    value class DCQLCredentialSetQueryPurposeObject(val jsonObject: JsonObject) :
        DCQLCredentialSetQueryPurpose

    @JvmInline
    value class DCQLCredentialSetQueryPurposeString(val string: String) :
        DCQLCredentialSetQueryPurpose

    sealed interface DCQLCredentialSetQueryPurposeNumber : DCQLCredentialSetQueryPurpose

    @JvmInline
    value class DCQLCredentialSetQueryPurposeLong(val long: Long) : DCQLCredentialSetQueryPurposeNumber

    @JvmInline
    value class DCQLCredentialSetQueryPurposeDouble(val double: Double) : DCQLCredentialSetQueryPurposeNumber
}