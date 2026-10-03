"""Every registered tool carries annotations that match what it does."""

import asyncio

import pytest

from monarch_mcp_server import tool_annotations
from monarch_mcp_server.app import mcp


@pytest.fixture(scope="module")
def tools():
    return {tool.name: tool for tool in asyncio.run(mcp.list_tools())}


def test_every_tool_is_annotated(tools):
    missing = [name for name, tool in tools.items() if tool.annotations is None]
    assert missing == []


def test_classified_names_are_registered(tools):
    # A typo or a renamed tool would otherwise silently fall back to
    # "destructive write", and a read would show up as a write again.
    listed = tool_annotations.READ_ONLY_TOOLS | tool_annotations.ADDITIVE_TOOLS
    assert sorted(listed - tools.keys()) == []


def test_read_tools_are_read_only(tools):
    for name, tool in tools.items():
        is_read = name in tool_annotations.READ_ONLY_TOOLS
        assert tool.annotations.readOnlyHint is is_read, name


def test_getters_are_never_classified_as_writes(tools):
    getters = {n for n in tools if n.startswith(("get_", "search_"))}
    assert getters <= tool_annotations.READ_ONLY_TOOLS


@pytest.mark.parametrize(
    ("name", "destructive"),
    [
        ("delete_account", True),
        ("delete_transaction", True),
        ("reset_budget", True),
        ("set_budget_amount", True),
        ("update_transaction", True),
        ("monarch_logout", True),
        ("create_transaction", False),
        ("upload_receipt_to_inbox", False),
        ("refresh_accounts", False),
    ],
)
def test_write_tools_report_destructiveness(tools, name, destructive):
    annotations = tools[name].annotations
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is destructive


def test_explicit_annotations_win():
    from mcp.types import ToolAnnotations

    class Recorder:
        def tool(self, *args, **kwargs):
            self.kwargs = kwargs
            return lambda fn: fn

    recorder = Recorder()
    tool_annotations.install(recorder)
    explicit = ToolAnnotations(readOnlyHint=True)

    @recorder.tool(annotations=explicit)
    def delete_account():
        pass

    assert recorder.kwargs["annotations"] is explicit
