package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor

class AntlrJsonPathTypeCheckerVisitor(
    private val compiler: JsonPathCompiler,
    private val errorListener: AntlrJsonPathTypeCheckerErrorListener?,
    private val functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
) : JsonPathParserBaseVisitor<AntlrJsonPathTypeCheckerExpressionType>() {
    // see section 2.4.3: Well-Typedness of Function Expressions
    // - https://datatracker.ietf.org/doc/rfc9535/

    override fun defaultResult(): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.NoType
    }
    override fun aggregateResult(
        aggregate: AntlrJsonPathTypeCheckerExpressionType?,
        nextResult: AntlrJsonPathTypeCheckerExpressionType
    ): AntlrJsonPathTypeCheckerExpressionType {
        if (aggregate == AntlrJsonPathTypeCheckerExpressionType.ErrorType) {
            return AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
        return nextResult
    }

    override fun visitFilter_query(ctx: JsonPathParser.Filter_queryContext): AntlrJsonPathTypeCheckerExpressionType {
        return if (compiler.compile("$${ctx.text.substring(1)}").isSingularQuery) {
            AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery
        } else {
            AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.NonSingularQuery
        }
    }

    override fun visitSingular_query(ctx: JsonPathParser.Singular_queryContext): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery
    }

    override fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        return visitLogical_or_expr(ctx.logical_or_expr())
    }

    override fun visitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        return if (ctx.logical_and_expr().map { visitLogical_and_expr(it) }.any {
                it is AntlrJsonPathTypeCheckerExpressionType.ErrorType
            }) {
            AntlrJsonPathTypeCheckerExpressionType.ErrorType
        } else {
            AntlrJsonPathTypeCheckerExpressionType.LogicalType
        }
    }

    override fun visitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        val isError = ctx.basic_expr().map { visitBasic_expr(it) }.any {
            it is AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
        return if (isError) {
            AntlrJsonPathTypeCheckerExpressionType.ErrorType
        } else {
            AntlrJsonPathTypeCheckerExpressionType.LogicalType
        }
    }

    override fun visitLiteral(ctx: JsonPathParser.LiteralContext): AntlrJsonPathTypeCheckerExpressionType {
        return AntlrJsonPathTypeCheckerExpressionType.ValueType
    }

    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        return ctx.function_expr()?.let { functionExpressionContext ->
            when (visitFunction_expr(functionExpressionContext)) {
                is AntlrJsonPathTypeCheckerExpressionType.ValueType -> {
                    errorListener
                        ?.invalidFunctionExtensionForTestExpression(
                            functionExpressionContext.FUNCTION_NAME().text,
                        )
                    AntlrJsonPathTypeCheckerExpressionType.ErrorType
                }
                is AntlrJsonPathTypeCheckerExpressionType.ErrorType -> AntlrJsonPathTypeCheckerExpressionType.ErrorType

                else -> AntlrJsonPathTypeCheckerExpressionType.LogicalType
            }
        } ?: AntlrJsonPathTypeCheckerExpressionType.LogicalType // otherwise this is a filter query
    }

    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        val functionArgumentTypes = ctx.function_argument().map {
            visitFunction_argument(it)
        }
        val isFunctionArgumentsValid = functionArgumentTypes.all {
            it != AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }

        val extension =
            functionExtensionRetriever.invoke(ctx.FUNCTION_NAME().text)
                ?: return AntlrJsonPathTypeCheckerExpressionType.ErrorType
                    .also {
                        errorListener?.unknownFunctionExtension(ctx.FUNCTION_NAME().text)
                    }

        val isArglistSizeConsistent = ctx.function_argument().size == extension.argumentTypes.size
        val coercedArgumentTypes = functionArgumentTypes.mapIndexed { index, argumentType ->
            val expectedArgumentType = extension.argumentTypes.getOrNull(index)

            when (expectedArgumentType) {
                JsonPathExpressionType.LogicalType -> when (argumentType) {
                    is AntlrJsonPathTypeCheckerExpressionType.NodesType -> JsonPathExpressionType.LogicalType

                    else -> argumentType.jsonPathExpressionType
                }

                JsonPathExpressionType.NodesType -> argumentType.jsonPathExpressionType // no conversions

                JsonPathExpressionType.ValueType -> when (argumentType) {
                    is AntlrJsonPathTypeCheckerExpressionType.NodesType.FilterQuery.SingularQuery -> JsonPathExpressionType.ValueType
                    else -> argumentType.jsonPathExpressionType
                }

                null -> argumentType.jsonPathExpressionType
            }
        }

        val isCoercedArgumentTypesMatching =
            coercedArgumentTypes.mapIndexed { index, jsonPathExpressionType ->
                jsonPathExpressionType == extension.argumentTypes.get(index)
            }.all {
                it
            }

        if ((isArglistSizeConsistent == false) or (isCoercedArgumentTypesMatching == false)) {
            errorListener?.invalidArglistForFunctionExtension(
                functionExtension = extension,
                coercedArgumentTypes = coercedArgumentTypes,
            )
        }

        return if (isArglistSizeConsistent and isCoercedArgumentTypesMatching and isFunctionArgumentsValid) {
            when (extension) {
                is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.LogicalType
                is JsonPathFunctionExtension.NodesTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.NodesType.FunctionNodesType
                is JsonPathFunctionExtension.ValueTypeFunctionExtension -> AntlrJsonPathTypeCheckerExpressionType.ValueType
            }
        } else {
            AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
    }

    override fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): AntlrJsonPathTypeCheckerExpressionType {
        // evaluate all comparables in order to find as many errors as possible
        // otherwise, a comparison always returns a boolean anyway
        val isValidComparableTypes = ctx.comparable().map { comparableContext ->
            val comparable = visitComparable(comparableContext)
            comparableContext.function_expr()?.let { functionExpressionContext ->
                if (comparable !is AntlrJsonPathTypeCheckerExpressionType.ValueType) {
                    errorListener?.invalidFunctionExtensionForComparable(
                        functionExpressionContext.FUNCTION_NAME().text,
                    )
                }
            }
            comparableContext.singular_query()?.let {
                AntlrJsonPathTypeCheckerExpressionType.ValueType
            } ?: comparable
        }.all {
            it is AntlrJsonPathTypeCheckerExpressionType.ValueType
        }
        return if (isValidComparableTypes) {
            AntlrJsonPathTypeCheckerExpressionType.LogicalType
        } else {
            AntlrJsonPathTypeCheckerExpressionType.ErrorType
        }
    }
}

