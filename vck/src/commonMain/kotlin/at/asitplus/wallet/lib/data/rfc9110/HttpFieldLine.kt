package at.asitplus.wallet.lib.data.rfc9110

data class HttpFieldLine(
    val fieldName: HttpFieldName,
    val fieldValue: HttpFieldValue,
) {
    override fun toString() = "$fieldName: $fieldValue"
}