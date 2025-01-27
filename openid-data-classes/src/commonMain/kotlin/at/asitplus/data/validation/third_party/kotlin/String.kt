package at.asitplus.data.validation.third_party.kotlin

@Throws(IllegalArgumentException::class)
fun kotlin.String.requireIsNotEmpty() {
    require(isNotEmpty()) { "String must not be empty." }
}
