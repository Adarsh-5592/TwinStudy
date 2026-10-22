"""Apply the student's parent-sharing choices to dashboard summary payloads."""


def apply_parent_visibility(overview, task_progress, consistency, weekly_time, permissions):
    """Return copied dashboard sections with every disabled category masked."""
    overview = dict(overview)
    task_progress = dict(task_progress)
    consistency = dict(consistency)
    weekly_time = dict(weekly_time)

    if not permissions.get("tasks", False):
        for key in ("tasks_completed_ratio", "tasks_completed_pct"):
            overview[key] = None
        for key in ("total", "completed", "pending", "overdue", "progress_percent"):
            task_progress[key] = None
        task_progress["items"] = []

    if not permissions.get("consistency", False):
        overview["current_streak"] = None
        for key in ("current_streak", "longest_streak", "days_studied_this_week", "days_missed_this_week", "weekly_consistency_percent"):
            consistency[key] = None
        consistency["heatmap"] = []
    elif not permissions.get("study_time", False):
        consistency["heatmap"] = [
            {key: row[key] for key in ("day", "date", "status") if key in row}
            | {"studied": bool(row.get("hours", 0))}
            for row in consistency.get("heatmap", [])
        ]

    if not permissions.get("study_time", False):
        overview["weekly_study_time"] = None
        weekly_time["total_this_week"] = None
        weekly_time["total_last_week"] = None
        weekly_time["daily_breakdown"] = []

    if not permissions.get("exam_information", False):
        overview["upcoming_exam_days"] = None

    return overview, task_progress, consistency, weekly_time
