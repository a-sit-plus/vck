package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser
import at.asitplus.parser.generated.JSONPathParserBaseVisitor

class JSONPathTypeCheckerVisitor(
    private val compiler: JSONPathCompiler,
) : JSONPathParserBaseVisitor<Boolean>() {
    // see section 2.4.3: Well-Typedness of Function Expressions
    // - https://datatracker.ietf.org/doc/rfc9535/
    override fun aggregateResult(aggregate: Boolean?, nextResult: Boolean): Boolean =
        (aggregate ?: true) and nextResult

    override fun visitFunction_expr(ctx: JSONPathParser.Function_exprContext): Boolean {
        val isFunctionArgumentsValid = ctx.function_argument().all {
            visitFunction_argument(it)
        }

        val extension =
            compiler.getFunctionExtensionManager()?.getExtension(ctx.FUNCTION_NAME().text)
                ?: return false
                    .also { compiler.getErrorHandler()?.unknownFunctionExtension(ctx) }

        val isArglistSizeConsistent = ctx.function_argument().size != extension.argumentTypes.size
        val coercedArgumentTypes = ctx.function_argument().mapIndexed { index, argument ->
                val expectedArgumentType = extension.argumentTypes.getOrNull(index)

                val argumentFunctionExpression = argument.function_expr()
                val argumentExtension =
                    argumentFunctionExpression
                        ?.FUNCTION_NAME()?.text?.let {
                            compiler.getFunctionExtensionManager()?.getExtension(it)
                        }

                when (expectedArgumentType) {
                    JSONPathExpressionTypeEnum.LogicalType -> when {
                        argumentExtension is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> JSONPathExpressionTypeEnum.LogicalType
                        argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension -> JSONPathExpressionTypeEnum.LogicalType // can be coerced
                        argument.filter_query() != null -> JSONPathExpressionTypeEnum.LogicalType // can be coerced
                        argument.logical_expr() != null -> JSONPathExpressionTypeEnum.LogicalType

                        argument.literal() != null -> JSONPathExpressionTypeEnum.ValueType
                        argumentExtension is JSONPathFunctionExtension.ValueTypeFunctionExtension -> JSONPathExpressionTypeEnum.ValueType // can't be coerced
                        else -> null
                    }

                    JSONPathExpressionTypeEnum.NodesType -> when {
                        argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension -> JSONPathExpressionTypeEnum.NodesType // can be coerced
                        argument.filter_query() != null -> JSONPathExpressionTypeEnum.NodesType

                        argument.literal() != null -> JSONPathExpressionTypeEnum.ValueType
                        argument.logical_expr() != null -> JSONPathExpressionTypeEnum.LogicalType
                        argumentExtension is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> JSONPathExpressionTypeEnum.LogicalType // can't be coerced
                        argumentExtension is JSONPathFunctionExtension.ValueTypeFunctionExtension -> JSONPathExpressionTypeEnum.ValueType // can't be coerced
                        else -> null
                    }

                    JSONPathExpressionTypeEnum.ValueType -> when {
                        argumentExtension is JSONPathFunctionExtension.ValueTypeFunctionExtension -> JSONPathExpressionTypeEnum.ValueType
                        argument.literal() != null -> JSONPathExpressionTypeEnum.ValueType
                        argument.filter_query() != null -> argument.filter_query()?.text?.let {
                            // must be a singular query
                            val asAbsQuery = "$${it.substring(1)}"
                            if(compiler.compile(asAbsQuery).isSingularQuery) JSONPathExpressionTypeEnum.ValueType
                            else JSONPathExpressionTypeEnum.NodesType
                        }

                        argument.logical_expr() != null -> JSONPathExpressionTypeEnum.LogicalType
                        argumentExtension is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> JSONPathExpressionTypeEnum.LogicalType
                        argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension -> JSONPathExpressionTypeEnum.NodesType
                        else -> null
                    }

                    null -> when {
                        argumentExtension is JSONPathFunctionExtension.ValueTypeFunctionExtension -> JSONPathExpressionTypeEnum.ValueType
                        argumentExtension is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> JSONPathExpressionTypeEnum.LogicalType
                        argumentExtension is JSONPathFunctionExtension.NodesTypeFunctionExtension -> JSONPathExpressionTypeEnum.NodesType
                        argument.literal() != null -> JSONPathExpressionTypeEnum.ValueType
                        argument.filter_query() != null -> JSONPathExpressionTypeEnum.NodesType
                        argument.logical_expr() != null -> JSONPathExpressionTypeEnum.LogicalType
                        else -> null
                    }
                }
            }

        val isCoercedArgumentTypesMatching = coercedArgumentTypes.zip(extension.argumentTypes).any {
            it.first != it.second
        }

        if((isArglistSizeConsistent == false) or (isCoercedArgumentTypesMatching == false)) {
            compiler.getErrorHandler()?.invalidArglistForFunctionExtension(
                functionExtension = extension,
                coercedArgumentTypes = coercedArgumentTypes,
            )
        }

        return isArglistSizeConsistent and isCoercedArgumentTypesMatching and isFunctionArgumentsValid
    }

    override fun visitTest_expr(ctx: JSONPathParser.Test_exprContext): Boolean {
        return ctx.function_expr()?.let { functionExpressionContext ->
            val isFunctionExprValid = visitFunction_expr(functionExpressionContext)

            val isValidTestExpressionReturnType =
                when (compiler.getFunctionExtensionManager()
                    ?.getExtension(functionExpressionContext.FUNCTION_NAME().text)) {
                    is JSONPathFunctionExtension.NodesTypeFunctionExtension -> true
                    is JSONPathFunctionExtension.LogicalTypeFunctionExtension -> true
                    null -> false
                    else -> {
                        compiler.getErrorHandler()
                            ?.invalidFunctionExtensionReturnTypeForTestExpression(
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
                val extension = compiler.getFunctionExtensionManager()
                    ?.getExtension(functionExpressionContext.FUNCTION_NAME().text)
                when (extension) {
                    null -> {} // unknown function is reported in visitComparable
                    is JSONPathFunctionExtension.ValueTypeFunctionExtension -> {}
                    else -> {
                        compiler.getErrorHandler()?.invalidFunctionExtensionReturnTypeForComparable(
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