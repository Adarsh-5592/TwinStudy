import unittest

from parent_visibility import apply_parent_visibility


class ParentVisibilityTests(unittest.TestCase):
    def test_disabled_categories_mask_summary_and_detail_fields(self):
        overview, tasks, consistency, study_time = apply_parent_visibility(
            {
                "tasks_completed_ratio": "3/7", "tasks_completed_pct": 42,
                "current_streak": 9, "weekly_study_time": "2h 0m", "upcoming_exam_days": 5,
            },
            {"total": 7, "completed": 3, "pending": 4, "overdue": 1, "progress_percent": 42,
             "items": [{"id": "private"}]},
            {"permitted": False, "current_streak": 9, "longest_streak": 10,
             "days_studied_this_week": 4, "days_missed_this_week": 3,
             "weekly_consistency_percent": 57, "heatmap": [{"date": "private"}]},
            {"permitted": False, "total_this_week": "2h 0m", "total_last_week": "4h 0m",
             "daily_breakdown": [{"date": "private"}]},
            {"tasks": False, "consistency": False, "study_time": False, "exam_information": False},
        )
        for key in ("tasks_completed_ratio", "tasks_completed_pct", "current_streak", "weekly_study_time", "upcoming_exam_days"):
            self.assertIsNone(overview[key])
        for key in ("total", "completed", "pending", "overdue", "progress_percent"):
            self.assertIsNone(tasks[key])
        self.assertEqual(tasks["items"], [])
        for key in ("current_streak", "longest_streak", "days_studied_this_week", "days_missed_this_week", "weekly_consistency_percent"):
            self.assertIsNone(consistency[key])
        self.assertEqual(consistency["heatmap"], [])
        self.assertIsNone(study_time["total_this_week"])
        self.assertIsNone(study_time["total_last_week"])
        self.assertEqual(study_time["daily_breakdown"], [])

    def test_enabled_categories_keep_values_and_inputs_are_not_mutated(self):
        overview = {"current_streak": 4}
        tasks = {"total": 2, "items": [{"id": "visible"}]}
        consistency = {"current_streak": 4, "heatmap": [{"day": "MON"}]}
        study_time = {"total_this_week": "1h 0m", "daily_breakdown": [{"day": "MON"}]}
        masked = apply_parent_visibility(overview, tasks, consistency, study_time, {
            "tasks": True, "consistency": True, "study_time": True, "exam_information": True,
        })
        self.assertEqual(masked[0], overview)
        self.assertEqual(masked[1], tasks)
        self.assertEqual(masked[2], consistency)
        self.assertEqual(masked[3], study_time)
        self.assertIsNot(masked[0], overview)

    def test_consistency_can_be_shared_without_exact_study_hours(self):
        _overview, _tasks, consistency, weekly_time = apply_parent_visibility(
            {}, {}, {"permitted": True, "heatmap": [
                {"day": "MON", "date": "2026-10-19", "status": "studied", "hours": 2.5},
                {"day": "TUE", "date": "2026-10-20", "status": "missed", "hours": 0},
            ]},
            {"permitted": False, "total_this_week": None, "daily_breakdown": []},
            {"consistency": True, "study_time": False},
        )
        self.assertEqual(consistency["heatmap"][0]["studied"], True)
        self.assertNotIn("hours", consistency["heatmap"][0])
        self.assertIsNone(weekly_time["total_this_week"])


if __name__ == "__main__":
    unittest.main()
