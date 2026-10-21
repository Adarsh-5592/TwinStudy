"""Pure endpoint role policy shared by the API guard and regression tests."""

STUDENT_ONLY_API_ENDPOINTS = frozenset({
    "extract_academic_documents", "save_academic_calendar_events", "save_academic",
    "create_student_task", "delete_task_route", "generate_student_tasks",
    "update_student_profile", "log_telemetry_session",
    "get_student_parent_settings", "update_student_parent_permissions",
    "approve_parent_access", "revoke_parent_access",
    "chat_message_route", "chat_document_message_route", "decision_feedback_route",
    "run_simulation_route", "generate_proof_quiz", "submit_task_proof",
    "get_twin_health", "log_twin_decision", "submit_twin_feedback",
    "update_twin_pattern", "delete_twin_pattern", "reset_twin_weights",
    "toggle_privacy_setting", "get_grades_overview", "record_new_grade",
    "update_grade_target", "delete_grade", "get_user_exams", "add_new_exam",
    "delete_exam", "get_user_goals", "add_new_goal", "delete_goal",
})
STUDENT_ROLES = frozenset({"student", "student_adult", "student_minor"})
PARENT_ONLY_API_ENDPOINTS = frozenset({"parent_link_student", "get_parent_dashboard_data"})
PARENT_ROLES = frozenset({"parent", "guardian"})
OPERATOR_ONLY_API_ENDPOINTS = frozenset({"smtp_status", "configure_smtp", "test_smtp"})
SHARED_SESSION_API_ENDPOINTS = frozenset({"get_state", "auth_me", "auth_logout"})
SESSION_ROLES = STUDENT_ROLES | PARENT_ROLES | frozenset({"admin"})


def requires_student_role(endpoint: str) -> bool:
    """Return whether an endpoint is student-only, including Vercel aliases."""
    base_endpoint = endpoint[:-6] if endpoint.endswith("_alias") else endpoint
    return base_endpoint in STUDENT_ONLY_API_ENDPOINTS


def is_student_role(role: str) -> bool:
    return role in STUDENT_ROLES


def endpoint_role_allowed(endpoint: str, role: str) -> bool:
    """Allow only explicitly classified role/endpoint combinations."""
    base_endpoint = endpoint[:-6] if endpoint.endswith("_alias") else endpoint
    if base_endpoint in OPERATOR_ONLY_API_ENDPOINTS:
        return role == "admin"
    if requires_student_role(base_endpoint):
        return is_student_role(role)
    if base_endpoint in PARENT_ONLY_API_ENDPOINTS:
        return role in PARENT_ROLES
    if base_endpoint in SHARED_SESSION_API_ENDPOINTS:
        return role in SESSION_ROLES
    return False
