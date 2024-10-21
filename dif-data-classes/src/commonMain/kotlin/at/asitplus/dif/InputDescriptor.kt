package at.asitplus.dif

interface InputDescriptor {
    val id: String
    val group: String?
    val name: String?
    val purpose: String?
    val format: FormatHolder?
    val constraints: Constraint?
}
