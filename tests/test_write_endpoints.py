"""Coverage for write methods exposed from monarchmoneycommunity."""

import base64
import json

from monarch_mcp_server.tools.accounts import create_manual_account, delete_account
from monarch_mcp_server.tools.attachments import (
    upload_receipt_to_inbox,
    upload_transaction_attachment,
)
from monarch_mcp_server.tools.budgets import reset_budget, update_flexible_budget
from monarch_mcp_server.tools.categories import (
    delete_transaction_categories,
    delete_transaction_category,
)


# The mutating methods listed by MonarchMoneyCommunity's public documentation.
# Values are the MCP tools that expose each capability; a few intentionally use
# clearer names or a richer custom GraphQL implementation.
DOCUMENTED_WRITE_API_TO_MCP_TOOL = {
    "delete_transaction_category": "delete_transaction_category",
    "delete_transaction_categories": "delete_transaction_categories",
    "create_transaction_category": "create_transaction_category",
    "request_accounts_refresh": "refresh_accounts",
    "request_accounts_refresh_and_wait": "refresh_accounts_and_wait",
    "create_transaction": "create_transaction",
    "update_transaction": "update_transaction",
    "update_reoccuring": "update_merchant",
    "delete_transaction": "delete_transaction",
    "update_transaction_splits": "split_transaction",
    "create_transaction_tag": "create_transaction_tag",
    "set_transaction_tags": "set_transaction_tags",
    "set_budget_amount": "set_budget_amount",
    "update_flexible_budget": "update_flexible_budget",
    "update_flex_rollover_settings": "update_flex_rollover_settings",
    "reset_budget": "reset_budget",
    "create_manual_account": "create_manual_account",
    "delete_account": "delete_account",
    "update_account": "update_account",
    "upload_account_balance_history": "upload_account_balance_history",
    "upload_attachment": "upload_transaction_attachment",
    "upload_receipt_to_inbox": "upload_receipt_to_inbox",
}


async def test_every_documented_upstream_write_api_has_a_registered_tool():
    from monarch_mcp_server.app import mcp

    registered = {tool.name for tool in await mcp.list_tools()}
    missing = {
        api: tool
        for api, tool in DOCUMENTED_WRITE_API_TO_MCP_TOOL.items()
        if tool not in registered
    }
    assert not missing, f"documented upstream writes missing MCP tools: {missing}"


async def test_create_manual_account_maps_public_arguments(mock_monarch_client):
    await create_manual_account("Cash", "asset", "cash", 25.5, False)
    mock_monarch_client.create_manual_account.assert_awaited_once_with(
        account_type="asset",
        account_sub_type="cash",
        is_in_net_worth=False,
        account_name="Cash",
        account_balance=25.5,
    )


async def test_destructive_operations_require_confirmation(mock_monarch_client):
    for result in (
        await delete_account("acc-1"),
        await delete_transaction_category("cat-1"),
        await delete_transaction_categories(["cat-1"]),
        await reset_budget("2026-10-01"),
    ):
        assert "confirm=true" in json.loads(result)["message"]
    mock_monarch_client.delete_account.assert_not_awaited()
    mock_monarch_client.delete_transaction_category.assert_not_awaited()
    mock_monarch_client.delete_transaction_categories.assert_not_awaited()
    mock_monarch_client.reset_budget.assert_not_awaited()


async def test_category_bulk_delete_rejects_empty_list(mock_monarch_client):
    result = json.loads(await delete_transaction_categories([], confirm=True))
    assert "must not be empty" in result["message"]
    mock_monarch_client.delete_transaction_categories.assert_not_awaited()


async def test_flexible_budget_passes_only_supplied_values(mock_monarch_client):
    await update_flexible_budget(500, "2026-10-01")
    mock_monarch_client.update_flexible_budget.assert_awaited_once_with(
        amount=500, start_date="2026-10-01"
    )


async def test_receipt_inbox_decodes_base64(mock_monarch_client):
    data = base64.b64encode(b"receipt").decode()
    result = json.loads(await upload_receipt_to_inbox("receipt.jpg", data))
    assert result["size"] == 7
    mock_monarch_client.upload_receipt_to_inbox.assert_awaited_once_with(
        b"receipt", "receipt.jpg"
    )


async def test_transaction_attachment_uses_and_removes_temp_file(
    mock_monarch_client,
):
    seen = {}

    async def upload(**kwargs):
        with open(kwargs["file_path"], "rb") as handle:
            seen["content"] = handle.read()
        seen["path"] = kwargs["file_path"]
        return {"ok": True}

    mock_monarch_client.upload_attachment.side_effect = upload
    data = base64.b64encode(b"pdf bytes").decode()
    result = json.loads(
        await upload_transaction_attachment("txn-1", "receipt.pdf", data)
    )
    assert result["uploaded"] is True
    assert seen["content"] == b"pdf bytes"
    import os

    assert not os.path.exists(seen["path"])


async def test_upload_rejects_invalid_base64_before_client_lookup(
    mock_monarch_client,
):
    result = json.loads(await upload_receipt_to_inbox("x.jpg", "not base64"))
    assert "valid base64" in result["message"]
    mock_monarch_client.upload_receipt_to_inbox.assert_not_awaited()
