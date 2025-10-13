package at.asitplus.wallet.lib.extensions

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.jws.SdJwtSigned

val supportedSdAlgorithms = listOf(Digest.SHA256, Digest.SHA384, Digest.SHA512)

fun SdJwtSigned.Companion.sdHashInput(
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    filteredDisclosures: Set<String>,
) = (listOf(validSdJwtCredential.vcSerialized.substringBefore("~")) + filteredDisclosures)
    .joinToString("~", postfix = "~")


