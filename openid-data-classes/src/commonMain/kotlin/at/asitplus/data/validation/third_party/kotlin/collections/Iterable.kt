package at.asitplus.data.validation.third_party.kotlin.collections

@Throws(IllegalArgumentException::class)
fun <ValueType, KeyType : Any> kotlin.collections.Iterable<ValueType>.requireDistinctNotNull(
    identifier: (ValueType) -> KeyType?,
) {
    require(mapNotNull(identifier).let { it.distinct().size == it.size }) { "Iterable must not contain multiple elements with the same identifier." }
}

@Throws(IllegalArgumentException::class)
fun <ValueType, KeyType> kotlin.collections.Iterable<ValueType>.requireDistinct(identifier: (ValueType) -> KeyType) {
    require(map(identifier).let { it.distinct().size == it.size }) { "Iterable must not contain multiple elements with the same identifier." }
}
