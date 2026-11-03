package at.asitplus.csc.api

/** Converts a value passed from Java, which has no unsigned integers, rejecting values outside of [UInt]. */
internal fun Long.toUIntFromJava(name: String): UInt {
    require(this in 0..UInt.MAX_VALUE.toLong()) { "$name has to be in 0..${UInt.MAX_VALUE}, but was $this" }
    return toUInt()
}
