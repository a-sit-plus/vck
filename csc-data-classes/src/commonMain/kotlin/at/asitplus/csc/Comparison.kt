package at.asitplus.csc

/**
 * Checks if at least one Element is present
 */
infix fun Any?.or(other: Any?): Boolean =
    (this != null || other != null)

/**
 * Checks if either both are present or null
 */
infix fun Any?.iff(other: Any?): Boolean =
    (this == null) == (other == null)

/**
 * Checks if exactly one Element is not null
 */
infix fun Any?.xor(other: Any?): Boolean =
    (this == null) != (other == null)