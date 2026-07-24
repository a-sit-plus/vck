package at.asitplus.iso

interface ZkSystem {
    val zkSystemId: String
    val system: String
    val params: Map<String, Any>
}