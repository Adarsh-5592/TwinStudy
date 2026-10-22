import unittest
import ast
from pathlib import Path

from authorization import (
    OPERATOR_ONLY_API_ENDPOINTS,
    PARENT_ONLY_API_ENDPOINTS,
    SHARED_SESSION_API_ENDPOINTS,
    STUDENT_ONLY_API_ENDPOINTS,
    endpoint_role_allowed,
    requires_student_role,
)


class StudentEndpointAuthorizationTests(unittest.TestCase):
    def test_student_routes_reject_parent_and_unknown_roles(self):
        for endpoint in (
            "log_telemetry_session", "get_grades_overview", "get_user_exams",
            "get_user_goals", "update_twin_pattern", "toggle_privacy_setting",
        ):
            with self.subTest(endpoint=endpoint):
                self.assertFalse(endpoint_role_allowed(endpoint, "parent"))
                self.assertFalse(endpoint_role_allowed(endpoint, "teacher"))

    def test_student_routes_allow_all_student_account_roles(self):
        for endpoint in ("save_academic", "get_grades_overview", "get_user_goals"):
            for role in ("student", "student_adult", "student_minor"):
                with self.subTest(endpoint=endpoint, role=role):
                    self.assertTrue(endpoint_role_allowed(endpoint, role))

    def test_vercel_aliases_keep_the_same_role_policy(self):
        self.assertTrue(requires_student_role("get_grades_overview_alias"))
        self.assertFalse(endpoint_role_allowed("get_grades_overview_alias", "parent"))
        self.assertTrue(endpoint_role_allowed("get_parent_dashboard_data_alias", "parent"))

    def test_parent_routes_remain_available_to_parent_accounts(self):
        self.assertTrue(endpoint_role_allowed("get_parent_dashboard_data", "parent"))
        self.assertTrue(endpoint_role_allowed("parent_link_student", "parent"))
        self.assertFalse(endpoint_role_allowed("get_parent_dashboard_data", "student"))
        self.assertFalse(endpoint_role_allowed("parent_link_student", "student"))

    def test_smtp_credential_configuration_is_operator_only(self):
        for endpoint in ("configure_smtp", "test_smtp", "configure_smtp_alias"):
            for role in ("student", "student_adult", "student_minor", "parent"):
                with self.subTest(endpoint=endpoint, role=role):
                    self.assertFalse(endpoint_role_allowed(endpoint, role))
            self.assertTrue(endpoint_role_allowed(endpoint, "admin"))

    def test_policy_endpoint_names_match_actual_flask_views(self):
        root = Path(__file__).resolve().parent
        tree = ast.parse((root / "server.py").read_text(encoding="utf-8"))
        routed_views = set()
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                for decorator in node.decorator_list
            ):
                routed_views.add(node.name)
        server_tree = ast.parse((root / "server.py").read_text(encoding="utf-8"))
        public_assignment = next(
            node for node in server_tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "_PUBLIC_API_ENDPOINTS" for target in node.targets)
        )
        public_endpoints = frozenset(ast.literal_eval(public_assignment.value))
        classified = (
            STUDENT_ONLY_API_ENDPOINTS | PARENT_ONLY_API_ENDPOINTS
            | OPERATOR_ONLY_API_ENDPOINTS | SHARED_SESSION_API_ENDPOINTS
            | public_endpoints
        )
        self.assertEqual(classified, routed_views - {"serve_index"})
        self.assertIn("get_parent_dashboard_data", routed_views)
        self.assertNotIn("get_parent_dashboard_data", STUDENT_ONLY_API_ENDPOINTS)

    def test_unclassified_routes_default_to_denied(self):
        self.assertFalse(endpoint_role_allowed("future_unclassified_route", "student"))
        self.assertFalse(endpoint_role_allowed("future_unclassified_route", "parent"))


if __name__ == "__main__":
    unittest.main()
