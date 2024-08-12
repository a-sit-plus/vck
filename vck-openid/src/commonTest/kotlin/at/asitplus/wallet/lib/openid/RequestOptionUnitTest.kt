package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random

class RequestOptionUnitTest : FreeSpec({
    val scheme = ConstantIndex.AtomicAttribute2023
    val representations = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.ISO_MDOC
    )


    representations.forEach { representation ->
        "${representation.name}: RequestOptions -> InputDescriptor -> RequestOptions quasi equality" {
            repeat(3) {
                val reqOptions = RequestOptions(
                    credentialScheme = scheme,
                    representation = representation,
                    requestedAttributes = scheme.claimNames.randomSubList()
                )
                val inputDescriptor = reqOptions.toInputDescriptor()
                val reqOptionNew =
                    inputDescriptor.toRequestOptions()
                        ?: throw Exception("Couldn't create RequestOption inputDescriptor")
                reqOptionNew.requestedAttributes shouldBe reqOptions.requestedAttributes
                reqOptionNew.representation shouldBe reqOptions.representation
                reqOptionNew.credentialScheme shouldBe reqOptions.credentialScheme
            }
        }
    }
})

private fun <E> Collection<E>.randomSubList(): List<E> =
    this.shuffled().subList(0, Random.Default.nextInt(0, this.size))