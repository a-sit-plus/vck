package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

/**
 * Used to verify that ... the `credential` contain the `attributePath`?
 */
typealias PathAuthorizationValidator =
            (credential: SubjectCredentialStore.StoreEntry, attributePath: NormalizedJsonPath) -> Boolean