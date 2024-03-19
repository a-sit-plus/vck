package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.ConstantIndex

object EudiwPidCredentialScheme : ConstantIndex.CredentialScheme {
    override val schemaUri: String = "https://wallet.a-sit.at/schemas/1.0.0/EudiwPid1.json"
    override val vcType: String = "EudiwPid1"
    override val isoNamespace: String = "eu.europa.ec.eudiw.pid.1"
    override val isoDocType: String = "eu.europa.ec.eudiw.pid.1"
    override val claimNames: Collection<String> = listOf("family_name")
}