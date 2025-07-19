package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.msg.*
import at.asitplus.wallet.lib.nameHack
import at.asitplus.wallet.lib.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class ProblemReporterTest : FreeSpec({

    val problemReporter = ProblemReporter()

    "sorter" - {
        withData(nameFn = ::nameHack, ProblemReportSorter.values().asList()) {
            val report = ProblemReport(
                body = ProblemReportBody(
                    sorter = it,
                    scope = ProblemReportScope.MESSAGE,
                    descriptor = ProblemReportDescriptor.INTERNAL,
                    details = uuid4()
                ),
            )
            problemReporter.getProblemSorter(report) shouldBe it

            val reportText = ProblemReport(
                body = ProblemReportBody(
                    code = "${it.code}.m.me"
                ),
            )
            problemReporter.getProblemSorter(reportText) shouldBe it
        }
    }

    "scope" - {
        withData(nameFn = ::nameHack, ProblemReportScope.values().asList()) {
            val report = ProblemReport(
                body = ProblemReportBody(
                    sorter = ProblemReportSorter.WARNING,
                    scope = it,
                    descriptor = ProblemReportDescriptor.INTERNAL,
                    details = uuid4()
                ),
            )
            problemReporter.getProblemScope(report) shouldBe it

            val reportText = ProblemReport(
                body = ProblemReportBody(
                    code = "w.${it.code}.me"
                ),
            )
            problemReporter.getProblemScope(reportText) shouldBe it
        }
    }

    "descriptor" - {
        withData(nameFn = ::nameHack, ProblemReportDescriptor.values().asList()) {
            val report = ProblemReport(
                body = ProblemReportBody(
                    sorter = ProblemReportSorter.WARNING,
                    scope = ProblemReportScope.MESSAGE,
                    descriptor = it,
                    details = uuid4()
                ),
            )
            problemReporter.getProblemDescriptor(report) shouldBe it
            val reportText = ProblemReport(
                body = ProblemReportBody(
                    code = "w.m.${it.code}"
                ),
            )
            problemReporter.getProblemDescriptor(reportText) shouldBe it
        }
    }

    "explanationSimple" {
        val comment = uuid4()
        val problemReport = ProblemReport(
            body = ProblemReportBody(
                code = "foo",
                comment = comment
            )
        )

        problemReporter.buildExplanation(problemReport) shouldBe comment
    }

    "explanationPlaceholder" {
        val arg1 = uuid4()
        val arg2 = uuid4()
        val expectedComment = "Got $arg1, but expected $arg2"
        val comment = "Got {1}, but expected {2}"
        val problemReport = ProblemReport(
            body = ProblemReportBody(
                code = "foo",
                comment = comment,
                args = arrayOf(arg1, arg2)
            )
        )

        problemReporter.buildExplanation(problemReport) shouldBe expectedComment
    }

    "explanationTooManyPlaceholder" {
        val arg1 = uuid4()
        val expectedComment = "Got $arg1, but expected ?"
        val comment = "Got {1}, but expected {2}"
        val problemReport = ProblemReport(
            body = ProblemReportBody(
                code = "foo",
                comment = comment,
                args = arrayOf(arg1)
            )
        )

        problemReporter.buildExplanation(problemReport) shouldBe expectedComment
    }

})