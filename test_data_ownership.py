import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


def method_source(filename, class_name, method_name):
    tree = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method_name)
    return ast.get_source_segment((ROOT / filename).read_text(encoding="utf-8"), method)


class DatabaseOwnershipSourceTests(unittest.TestCase):
    def test_crud_mutations_include_the_authenticated_owner_in_sql(self):
        for name in ("delete_task", "delete_grade", "delete_exam", "delete_goal"):
            with self.subTest(method=name):
                source = method_source("db_manager.py", "DatabaseManager", name)
                self.assertIn("user_id = %s", source)
                self.assertIn("user_id", source)

    def test_academic_lookup_and_parent_decisions_are_student_scoped(self):
        subject = method_source("db_manager.py", "DatabaseManager", "get_user_subject")
        approve = method_source("db_manager.py", "DatabaseManager", "approve_parent_link")
        revoke = method_source("db_manager.py", "DatabaseManager", "revoke_parent_link")
        self.assertGreaterEqual(subject.count("user_id = %s"), 2)
        self.assertIn("student_id = %s", approve)
        self.assertIn("student_id = %s", revoke)

    def test_academic_route_tells_storage_to_preserve_existing_tasks(self):
        source = (ROOT / "server.py").read_text(encoding="utf-8")
        start = source.index('def save_academic():')
        end = source.find('\n@app.route', start)
        body = source[start:end]
        self.assertIn("preserve_existing_tasks=True", body)
        self.assertIn("db_mgr.get_user_tasks(user_id)", body)


if __name__ == "__main__":
    unittest.main()
