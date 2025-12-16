package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

class IsoPresentationMeta(
    val claims: Collection<NormalizedJsonPath>,
    val spec: SystemSpec = SystemSpec.Default
)