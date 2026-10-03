"""Receipt and transaction attachment write tools."""

import base64
import binascii
import os
import tempfile

from monarch_mcp_server.app import mcp
from monarch_mcp_server.client import get_monarch_client
from monarch_mcp_server.helpers import json_error, json_success

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _decode_upload(content_base64: str) -> bytes:
    """Decode a bounded base64 upload without exposing server file paths."""
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("content_base64 must be valid base64") from exc
    if not content:
        raise ValueError("uploaded content must not be empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("uploaded content exceeds the 10 MiB MCP limit")
    return content


@mcp.tool()
async def upload_transaction_attachment(
    transaction_id: str, filename: str, content_base64: str
) -> str:
    """Upload a base64-encoded receipt or document to one transaction.

    The server writes only a private temporary file and removes it after the
    upstream upload. Arbitrary local paths are deliberately not accepted.
    """
    path = None
    try:
        content = _decode_upload(content_base64)
        safe_name = os.path.basename(filename)
        if not safe_name or safe_name in {".", ".."}:
            raise ValueError("filename must include a valid file name")
        suffix = os.path.splitext(safe_name)[1]
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            handle.write(content)
            path = handle.name
        client = await get_monarch_client()
        result = await client.upload_attachment(
            transaction_id=transaction_id, file_path=path
        )
        return json_success(
            {
                "uploaded": True,
                "transaction_id": transaction_id,
                "filename": safe_name,
                "size": len(content),
                "result": result,
            }
        )
    except Exception as e:
        return json_error("upload_transaction_attachment", e)
    finally:
        if path is not None:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass


@mcp.tool()
async def upload_receipt_to_inbox(filename: str, content_base64: str) -> str:
    """Upload a base64-encoded receipt to Monarch's general receipt inbox."""
    try:
        content = _decode_upload(content_base64)
        safe_name = os.path.basename(filename)
        if not safe_name or safe_name in {".", ".."}:
            raise ValueError("filename must include a valid file name")
        client = await get_monarch_client()
        result = await client.upload_receipt_to_inbox(content, safe_name)
        return json_success(
            {
                "uploaded": True,
                "filename": safe_name,
                "size": len(content),
                "result": result,
            }
        )
    except Exception as e:
        return json_error("upload_receipt_to_inbox", e)
