package at.asitplus.wallet.lib.data.dif

data class PresentationOption(
    val inputDescriptors: Collection<InputDescriptor>,
) {
    companion object {
        fun findValidPresentationOptions(
            presentationDefinition: PresentationDefinition,
        ): Collection<PresentationOption> = findValidPresentationOptions(
            inputDescriptors = presentationDefinition.inputDescriptors,
            submissionRequirements = presentationDefinition.submissionRequirements,
        )

        private fun findValidPresentationOptions(
            inputDescriptors: Collection<InputDescriptor>,
            submissionRequirements: Collection<SubmissionRequirement>?,
        ): Collection<PresentationOption> {
            // TODO: support submission requirements feature
            return listOf(PresentationOption(inputDescriptors))
        }
    }
}