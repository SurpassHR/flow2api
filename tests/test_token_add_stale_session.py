import itertools
import tempfile
import unittest
from unittest.mock import AsyncMock

from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


STALE_SESSION = {
    "user": {"email": "stale@example.com", "name": "stale"},
    "expires": "2026-09-10T20:24:57.000Z",
    "access_token": "ya29.stale",
    "error": "ACCESS_TOKEN_REFRESH_NEEDED",
}


class StaleSessionDetectionTests(unittest.IsolatedAsyncioTestCase):
    """next-auth 在 access_token 刷不出来时仍返回 200，只带 error=ACCESS_TOKEN_REFRESH_NEEDED。
    这种会话能被 labs.google 认账号，但所有 Flow/PA 接口必然 401，必须提前报出真实原因。
    """

    def _client_returning(self, payload, warnings):
        client = FlowClient(proxy_manager=None)
        client._make_request = AsyncMock(return_value=payload)

        def record_warning(message):
            warnings.append(message)

        client_module_debug = client.__class__.__module__
        import src.services.flow_client as flow_client_module

        self._orig_warning = flow_client_module.debug_logger.log_warning
        flow_client_module.debug_logger.log_warning = record_warning
        self.addCleanup(
            lambda: setattr(
                flow_client_module.debug_logger, "log_warning", self._orig_warning
            )
        )
        return client

    async def test_st_to_at_preserves_payload_and_logs_stale_session_warning(self):
        warnings = []
        client = self._client_returning(dict(STALE_SESSION), warnings)

        payload = await client.st_to_at("st-test")

        self.assertEqual(payload["error"], "ACCESS_TOKEN_REFRESH_NEEDED")
        self.assertTrue(
            any("ACCESS_TOKEN_REFRESH_NEEDED" in message for message in warnings),
            warnings,
        )

    async def test_st_to_at_does_not_warn_for_healthy_session(self):
        warnings = []
        client = self._client_returning(
            {"user": {"email": "ok@example.com"}, "access_token": "ya29.ok"},
            warnings,
        )

        await client.st_to_at("st-test")

        self.assertEqual(warnings, [])


class AddTokenStaleSessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(db_path=f"{self._temp_dir.name}/flow.db")
        await self.db.init_db()

    async def asyncTearDown(self):
        self._temp_dir.cleanup()

    def _manager(self, payload):
        client = FlowClient(proxy_manager=None)
        client.st_to_at = AsyncMock(return_value=payload)
        client.get_credits = AsyncMock(return_value={"credits": 0})
        # 项目池会创建多个项目，project_id 在库里唯一，所以这里必须每次返回新 id
        counter = itertools.count(1)
        client.create_project = AsyncMock(
            side_effect=lambda *args, **kwargs: f"project-{next(counter)}"
        )
        return TokenManager(db=self.db, flow_client=client)

    async def test_add_token_reports_refresh_needed_instead_of_creating_project(self):
        manager = self._manager(dict(STALE_SESSION))

        with self.assertRaises(ValueError) as ctx:
            await manager.add_token(st="st-stale")

        message = str(ctx.exception)
        self.assertIn("ACCESS_TOKEN_REFRESH_NEEDED", message)
        self.assertIn("重新获取", message)
        # 关键：不应再把过期会话拿去调 createProject（那就是现场那个 HTTP 401）
        manager.flow_client.create_project.assert_not_awaited()
        manager.flow_client.get_credits.assert_not_awaited()

    async def test_add_token_rejects_payload_without_access_token(self):
        manager = self._manager({"user": {"email": "x@example.com"}})

        with self.assertRaises(ValueError) as ctx:
            await manager.add_token(st="st-stale")

        self.assertIn("缺少 access_token", str(ctx.exception))
        manager.flow_client.create_project.assert_not_awaited()

    async def test_credits_failure_still_adds_token(self):
        manager = self._manager(
            {"user": {"email": "ok@example.com"}, "access_token": "ya29.ok"}
        )
        manager.flow_client.get_credits = AsyncMock(
            side_effect=Exception("Flow API request failed: HTTP Error 401")
        )

        token = await manager.add_token(st="st-ok")

        self.assertEqual(token.email, "ok@example.com")
        self.assertEqual(token.credits, 0)

    async def test_duplicate_session_token_message_is_readable(self):
        await self.db.add_token(
            Token(st="st-dup", at="at-dup", email="dup@example.com", name="dup")
        )
        manager = self._manager(
            {"user": {"email": "dup@example.com"}, "access_token": "ya29.ok"}
        )

        with self.assertRaises(ValueError) as ctx:
            await manager.add_token(st="st-dup")

        self.assertEqual(str(ctx.exception), "Token 已存在（邮箱: dup@example.com）")


if __name__ == "__main__":
    unittest.main()
