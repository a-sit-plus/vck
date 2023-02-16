package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.msg.*


class ProblemReporter {

    fun getProblemSorter(problemReport: ProblemReport) =
        problemReport.body.code.split(".").let {
            if (it.isNotEmpty()) ProblemReportSorter.parseCode(it[0]) else null
        }

    fun getProblemScope(problemReport: ProblemReport) =
        problemReport.body.code.split(".").let {
            if (it.size >= 2) ProblemReportScope.parseCode(it[1]) else null
        }

    fun getProblemDescriptor(problemReport: ProblemReport) =
        problemReport.body.code.split(".").let {
            if (it.size >= 3) ProblemReportDescriptor.parseCode(it[2]) else null
        }

    /**
     * Builds explanation by injecting [ProblemReportBody.args] into [ProblemReportBody.comment]
     */
    fun buildExplanation(problemReport: ProblemReport): String? {
        problemReport.body.comment?.let { comment ->
            var result = comment
            problemReport.body.args?.let { args ->
                args.forEachIndexed { index, s -> result = result.replace("{${index + 1}}", s) }
                return """\{\d}""".toRegex().replace(result, "?")
            }
            return """\{\d}""".toRegex().replace(result, "?")
        }
        return null
    }

    fun problemLastMessage(parentThreadId: String?, code: String) =
        InternalNextMessage.SendProblemReport(
            ProblemReport(
                body = ProblemReportBody(
                    sorter = ProblemReportSorter.WARNING,
                    scope = ProblemReportScope.MESSAGE,
                    descriptor = ProblemReportDescriptor.MESSAGE,
                    details = code
                ),
                parentThreadId = parentThreadId
            )
        )

    fun problemInternal(parentThreadId: String?, code: String) =
        InternalNextMessage.SendProblemReport(
            ProblemReport(
                body = ProblemReportBody(
                    sorter = ProblemReportSorter.ERROR,
                    scope = ProblemReportScope.MESSAGE,
                    descriptor = ProblemReportDescriptor.INTERNAL,
                    details = code
                ),
                parentThreadId = parentThreadId
            )
        )

    fun problemRequirement(parentThreadId: String?, code: String, comment: String, vararg args: String) =
        InternalNextMessage.SendProblemReport(
            ProblemReport(
                body = ProblemReportBody(
                    sorter = ProblemReportSorter.ERROR,
                    scope = ProblemReportScope.MESSAGE,
                    descriptor = ProblemReportDescriptor.REQUIREMENTS,
                    details = code,
                    comment = comment,
                    args = arrayOf(*args)
                ),
                parentThreadId = parentThreadId
            )
        )

}
