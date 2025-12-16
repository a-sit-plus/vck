package at.asitplus.wallet.lib.agent

import at.asitplus.iso.ZkSystemSpec

data class SystemSpec(
    val allowedZkSpec: List<ZkSystemSpec>,
    val forceZk: Boolean = false
) {
    init {
        require(!forceZk || allowedZkSpec.isNotEmpty()) { "ZkSpec cannot be empty if Zero-Knowledge is enforced" }
    }

    companion object {
        val Default = SystemSpec(listOf(), false)
    }
}
