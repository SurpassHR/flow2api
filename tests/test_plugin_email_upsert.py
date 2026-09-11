import itertools
import tempfile
import unittest
from unittest.mock import AsyncMock

from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager
from src.api import admin


SESSION = {
    "user": {"email": "Hu.Rui0530@Gmail.com", "name": "rui"},
    "expires": "2026-10-11T00:24:57.000Z",
    "access_token": "ya29.fresh",
}


class EmailLookupToleranceTests(unittest.IsolatedAsyncioTestCase):
    """邮箱必须大小写/空格不敏感，否则插件同步会给同一账号插入第二行。"""

    async def asyncSetUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(db_path=f"{self._temp_dir.name}/flow.db")
        await self.db.init_db()
        self.token_id = await self.db.add_token(
            Token(st="st-old", at="at-old", email="hu.rui0530@gmail.com", name="rui")
        )

    async def asyncTearDown(self):
        self._temp_dir.cleanup()

    async def test_exact_match_still_works(self):
        token = await self.db.get_token_by_email("hu.rui0530@gmail.com")
        self.assertIsNotNone(token)
        self.assertEqual(token.id, self.token_id)

    async def test_case_differs(self):
        token = await self.db.get_token_by_email("Hu.Rui0530@Gmail.com")
        self.assertIsNotNone(token, "大小写不同应视为同一账号")
        self.assertEqual(token.id, self.token_id)

    async def test_surrounding_whitespace(self):
        token = await self.db.get_token_by_email("  hu.rui0530@gmail.com  ")
        self.assertIsNotNone(token, "首尾空格应被忽略")
        self.assertEqual(token.id, self.token_id)

    async def test_empty_email_returns_none(self):
        self.assertIsNone(await self.db.get_token_by_email(""))
        self.assertIsNone(await self.db.get_token_by_email("   "))


class PluginUpsertRoutingTests(unittest.IsolatedAsyncioTestCase):
    """插件端点 /api/plugin/update-token 必须按邮箱分流：已存在则更新，不存在才新增。"""

    async def asyncSetUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(db_path=f"{self._temp_dir.name}/flow.db")
        await self.db.init_db()
        await self.db.update_plugin_config("conn-token", True)

        client = FlowClient(proxy_manager=None)
        client.st_to_at = AsyncMock(return_value=dict(SESSION))
        self.manager = TokenManager(db=self.db, flow_client=client)
        self.manager.update_token = AsyncMock()
        self.manager.add_token = AsyncMock(
            return_value=Token(id=99, st="st-new", at="at-new", email=SESSION["user"]["email"])
        )
        self.manager.enable_token = AsyncMock()

        self._prev = (admin.db, admin.token_manager)
        admin.set_dependencies(self.manager, None, self.db, None)

    async def asyncTearDown(self):
        admin.db, admin.token_manager = self._prev
        self._temp_dir.cleanup()

    async def _call(self, **extra):
        request = {"session_token": "st-new", **extra}
        return await admin.plugin_update_token(
            request=request, authorization="Bearer conn-token"
        )

    async def test_existing_account_with_different_case_updates_instead_of_adding(self):
        token_id = await self.db.add_token(
            Token(st="st-old", at="at-old", email="hu.rui0530@gmail.com", name="rui")
        )

        result = await self._call()

        self.assertEqual(result["action"], "updated")
        self.manager.add_token.assert_not_awaited()
        self.manager.update_token.assert_awaited_once()
        kwargs = self.manager.update_token.await_args.kwargs
        self.assertEqual(kwargs["token_id"], token_id)
        self.assertEqual(kwargs["st"], "st-new")
        self.assertEqual(kwargs["at"], "ya29.fresh")

    async def test_unknown_account_is_added(self):
        result = await self._call()

        self.assertEqual(result["action"], "added")
        self.assertEqual(result["token_id"], 99)
        self.manager.update_token.assert_not_awaited()
        self.manager.add_token.assert_awaited_once()

    async def test_missing_session_token_is_rejected(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            await admin.plugin_update_token(request={}, authorization="Bearer conn-token")

        self.assertEqual(ctx.exception.status_code, 400)
        self.manager.add_token.assert_not_awaited()
        self.manager.update_token.assert_not_awaited()

    async def test_bad_connection_token_is_rejected(self):
        from fastapi import HTTPException

        with self.assertRaises(HTTPException) as ctx:
            await admin.plugin_update_token(
                request={"session_token": "st-new"}, authorization="Bearer wrong"
            )

        self.assertEqual(ctx.exception.status_code, 401)


class AddTokenDuplicateVisibilityTests(unittest.IsolatedAsyncioTestCase):
    """add_token 允许同账号多 ST（现状），但重复插入必须留痕。"""

    async def asyncSetUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(db_path=f"{self._temp_dir.name}/flow.db")
        await self.db.init_db()
        await self.db.add_token(
            Token(st="st-old", at="at-old", email="dup@example.com", name="dup")
        )

        client = FlowClient(proxy_manager=None)
        client.st_to_at = AsyncMock(
            return_value={
                "user": {"email": "DUP@example.com"},
                "access_token": "ya29.ok",
            }
        )
        client.get_credits = AsyncMock(return_value={"credits": 5})
        counter = itertools.count(1)
        client.create_project = AsyncMock(
            side_effect=lambda *args, **kwargs: f"p{next(counter)}"
        )
        self.manager = TokenManager(db=self.db, flow_client=client)

    async def asyncTearDown(self):
        self._temp_dir.cleanup()

    async def test_duplicate_email_is_logged_not_blocked(self):
        import src.services.token_manager as token_manager_module

        warnings = []
        original = token_manager_module.debug_logger.log_warning
        token_manager_module.debug_logger.log_warning = warnings.append
        self.addCleanup(
            lambda: setattr(token_manager_module.debug_logger, "log_warning", original)
        )

        token = await self.manager.add_token(st="st-brand-new")

        self.assertEqual(token.email, "DUP@example.com")
        self.assertTrue(
            any("账号已存在" in message for message in warnings),
            warnings,
        )


if __name__ == "__main__":
    unittest.main()
