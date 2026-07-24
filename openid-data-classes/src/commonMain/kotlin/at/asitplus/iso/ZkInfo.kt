package at.asitplus.iso

interface ZkInfo {
    val zkRequired: Boolean
    val systemSpecs: List<ZkSystem>

    fun validate() {
        require(!zkRequired || systemSpecs.isNotEmpty()) {
            "systemSpecs list cannot be empty if Zero-Knowledge is enforced"
        }
        val ids = systemSpecs.map { it.zkSystemId }
        require(ids.size == ids.distinct().size) {
            "ZkSystemType IDs are not unique!"
        }
    }

}