package at.asitplus.data

import at.asitplus.data.validation.third_party.kotlin.collections.requireIsNotEmpty
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class NonEmptyList<out T>
@Throws(IllegalArgumentException::class) private constructor(val list: List<T>) : List<T> by list {
    init {
        requireIsNotEmpty()
    }

    companion object {
        fun <T> List<T>.toNonEmptyList() = NonEmptyList(this)
        fun <T> nonEmptyListOf(vararg elements: T) = NonEmptyList(elements.toList())
    }

    override fun toString(): String = "$list"
}