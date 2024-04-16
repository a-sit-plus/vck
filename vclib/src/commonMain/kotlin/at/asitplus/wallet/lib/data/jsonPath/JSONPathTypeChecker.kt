package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathParser

class JSONPathTypeChecker(
    val functionExtensionManager: JSONPathFunctionExtensionManager,
    val errorHandler: JSONPathErrorHandler,
) : JSONPathBaseVisitor<Boolean>() {
    override fun aggregateResult(aggregate: Boolean?, nextResult: Boolean): Boolean =
        (aggregate ?: true) and nextResult

    override fun visitFunction_expr(ctx: JSONPathParser.Function_exprContext): Boolean {
        val isFunctionArgumentsValid = ctx.function_argument().all {
            visitFunction_argument(it)
        }

        val extension = functionExtensionManager.getExtension(ctx.function_name().text)
        if (extension == null) {
            errorHandler.unknownFunctionExtension(ctx)
            return false
        }

        val isArgumentsConsistent =
            extension.argumentTypes.zip(ctx.function_argument()).map { argumentComparison ->
                val expectedArgumentType = argumentComparison.first
                val argument = argumentComparison.second

                val argumentFunctionExpression = argument.function_expr()
                val argumentExtension =
                    argumentFunctionExpression
                        ?.function_name()?.text?.let { functionExtensionManager.getExtension(it) }
                val isValidConversion = when (extension) {
                    is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> argument.logical_expr() != null
                            || argumentExtension is JSONPathFunctionExtension.LogicalTypeFunctionExtension
                            || argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension

                    is JSONPathFunctionExtension.NodesTypeFunctionExtension -> argument.filter_query() != null
                            || argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension

                    is JSONPathFunctionExtension.ValueTypeFunctionExtension -> argument.literal() != null
                            || argument.filter_query()?.text?.let {
                        // A singular query
                        val asAbsQuery = "$${it.substring(1)}"
                        JSONPathToJSONPathSelectorListCompiler(
                            functionExtensionManager = functionExtensionManager,
                            errorHandler = errorHandler,
                        ).compile(asAbsQuery).filter {
                            it !is JSONPathSelector.RootSelector
                        }.all {
                            it is JSONPathSelector.SingularQuerySelector
                        }
                    } == true
                            || argumentExtension is JSONPathFunctionExtension.ValueTypeFunctionExtension
                }
                argumentFunctionExpression?.let {
                    if (isValidConversion == false) {
                        errorHandler.invalidFunctionExtensionReturnTypeForFunctionArgumentType(
                            argumentFunctionExpression,
                            expectedArgumentType
                        )
                    }
                }
                isValidConversion
            }.all {
                it
            }

        return isArgumentsConsistent and isFunctionArgumentsValid
    }

    override fun visitTest_expr(ctx: JSONPathParser.Test_exprContext): Boolean {
        return ctx.function_expr()?.let { functionExpressionContext ->
            val isFunctionExprValid = visitFunction_expr(functionExpressionContext)

            val isValidTestExpressionReturnType =
                when (functionExtensionManager.getExtension(functionExpressionContext.function_name().text)) {
                    is JSONPathFunctionExtension.NodesTypeFunctionExtension -> true
                    is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> true
                    null -> false
                    else -> {
                        errorHandler.invalidFunctionExtensionReturnTypeForTestExpression(
                            functionExpressionContext
                        )
                        false
                    }
                }
            isFunctionExprValid and isValidTestExpressionReturnType
        } ?: true // otherwise this is a filter query and therefore testable
    }

    override fun visitComparison_expr(ctx: JSONPathParser.Comparison_exprContext): Boolean {
        // evaluate all comparables in order to find as many errors as possible
        // otherwise, a comparison always returns a boolean anyway
        return ctx.comparable().map {
            it.function_expr()?.let { functionExpressionContext ->
                when (functionExtensionManager.getExtension(functionExpressionContext.function_name().text)) {
                    null -> {}
                    is JSONPathFunctionExtension.ValueTypeFunctionExtension -> {}
                    else -> {
                        errorHandler.invalidFunctionExtensionReturnTypeForComparable(
                            functionExpressionContext
                        )
                    }
                }
            }
            visitComparable(it)
        }.all {
            it
        }
    }
}

