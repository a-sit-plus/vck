package at.asitplus.data.validation.third_party.kotlin.collections

object Collection {
    @Throws(IllegalArgumentException::class)
    fun <T> kotlin.collections.Collection<T>.requireIsNotEmpty() {
        require(isNotEmpty()) { "Collection must not be empty." }
    }
}