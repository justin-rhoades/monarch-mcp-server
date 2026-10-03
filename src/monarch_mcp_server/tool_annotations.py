"""MCP tool annotations: tell clients which tools only read.

A tool registered without annotations gets the MCP defaults, which assume the
worst: readOnlyHint=false and destructiveHint=true. Clients act on that.
ChatGPT, for one, lists every unannotated tool as a write action, so a plain
``get_accounts`` shows up next to ``delete_account`` with the same warning.

The read only tools are listed explicitly rather than matched by name prefix.
Anything not listed is treated as a destructive write, so a new tool that
nobody classified errs on the side of asking for confirmation.
"""

from typing import Any, Callable, FrozenSet, TypeVar

from mcp.types import ToolAnnotations

READ_ONLY_TOOLS: FrozenSet[str] = frozenset(
    {
        # Auth and diagnostics
        "setup_authentication",
        "check_auth_status",
        "debug_session_loading",
        "monarch_whoami",
        # Accounts
        "get_accounts",
        "get_account_holdings",
        "get_account_balance_history",
        "get_account_sync_health",
        # Transactions
        "get_transactions",
        "search_transactions",
        "get_transaction_details",
        "get_recurring_transactions",
        "get_transactions_needing_review",
        "get_transactions_summary",
        "get_spending_summary",
        "get_transaction_splits",
        "get_transaction_tags",
        "get_transaction_rules",
        # Categories and budgets
        "get_transaction_categories",
        "get_transaction_category_groups",
        "get_category_details",
        "get_cashflow_by_month",
        "get_budgets",
        "get_cashflow",
        # Net worth, debt, goals, merchants
        "get_net_worth",
        "get_net_worth_by_account_type",
        "get_debt_paydown",
        "get_goals",
        "get_goal_contributions",
        "get_merchant",
    }
)

# Writes that only add something new or ask Monarch to do work, and never
# overwrite or remove existing data.
ADDITIVE_TOOLS: FrozenSet[str] = frozenset(
    {
        "create_manual_account",
        "create_transaction",
        "create_transaction_tag",
        "create_transaction_rule",
        "create_transaction_category",
        "add_transaction_tag",
        "upload_transaction_attachment",
        "upload_receipt_to_inbox",
        "refresh_accounts",
        "refresh_accounts_and_wait",
    }
)

READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
ADDITIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, openWorldHint=True
)
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, openWorldHint=True
)

F = TypeVar("F", bound=Callable[..., Any])


def annotations_for(name: str) -> ToolAnnotations:
    if name in READ_ONLY_TOOLS:
        return READ_ONLY
    if name in ADDITIVE_TOOLS:
        return ADDITIVE
    return DESTRUCTIVE


def install(mcp: Any) -> None:
    """Make ``mcp.tool()`` attach annotations to every tool it registers.

    Wrapping registration keeps the tool modules unchanged: they all register
    through ``@mcp.tool()``. Annotations passed explicitly still win.
    """
    original_tool = mcp.tool

    def annotated_tool(*args: Any, **kwargs: Any) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            options = dict(kwargs)
            if options.get("annotations") is None:
                # FastMCP.tool() takes `name` as its first positional parameter.
                positional = args[0] if args and isinstance(args[0], str) else None
                name = positional or options.get("name") or fn.__name__
                options["annotations"] = annotations_for(name)
            result: F = original_tool(*args, **options)(fn)
            return result

        return decorator

    mcp.tool = annotated_tool  # type: ignore[method-assign]
