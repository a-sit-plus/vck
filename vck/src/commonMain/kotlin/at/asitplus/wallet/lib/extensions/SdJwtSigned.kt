package at.asitplus.wallet.lib.extensions

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.jws.SdJwtSigned

fun SdJwtSigned.Companion.sdHashInput(
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    filteredDisclosures: Set<String>,
) = (listOf(validSdJwtCredential.vcSerialized.substringBefore("~")) + filteredDisclosures)
    .joinToString("~", postfix = "~")


