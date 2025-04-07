package at.asitplus.dif

interface InputDescriptor {
    val id: String
    @Deprecated("To be replaced with groups, see #267")
    val group: String?
    val name: String?
    val purpose: String?
    val format: FormatHolder?
    val constraints: Constraint?
}
