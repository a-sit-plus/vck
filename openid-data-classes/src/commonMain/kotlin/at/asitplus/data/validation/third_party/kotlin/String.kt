package at.asitplus.data.validation.third_party.kotlin

object String {
    @Throws(IllegalArgumentException::class)
    fun kotlin.String.requireIsNotEmpty() {
        require(isNotEmpty()) { "String must not be empty." }
    }
}