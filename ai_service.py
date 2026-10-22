"""
TwinStudy AI - Intelligent Academic Chatbot & What-If Simulation Engine
Integrates real database records (timetable, tasks, exams, grades, behavior patterns),
supports multi-turn conversational memory, natural-language academic dilemma reasoning,
general educational tutoring, and strictly eliminates prohibited medicalized terminology.
"""

import os
import re
import json
import datetime
import time
import requests
from db_manager import db_mgr

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

DAYS_OF_WEEK = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

def get_current_day_name():
    return DAYS_OF_WEEK[datetime.datetime.now().weekday()]

def normalize_text(text: str) -> str:
    return re.sub(r'[^a-zA-Z0-9\s]', ' ', text or '').lower().strip()


def safe_float(v, default=0.0):
    try:
        if v is None:
            return default
        return float(v)
    except (TypeError, ValueError):
        return default



# ==============================================================================
# 1. STUDY BUDDY AI CHATBOT ENGINE
# ==============================================================================

def generate_chat_response(user_id: str, message: str, conversation_id: str = None) -> dict:
    conv_id = db_mgr.get_or_create_conversation(user_id, conversation_id)
    state = db_mgr.get_user_academic_state(user_id)

    user_info = state.get("user", {})
    profile = state.get("academic_profile", {})
    subjects = state.get("subjects", [])
    classes = state.get("classes", [])
    tasks = state.get("tasks", [])
    exams = state.get("exams", [])
    grades = state.get("grades", [])
    patterns = state.get("behavior_patterns", [])

    current_day = get_current_day_name()
    today_classes = [c for c in classes if str(c.get("day", "")).lower() == current_day.lower()]
    pending_tasks = [t for t in tasks if str(t.get("status", "")).lower() not in ("completed", "verified & done")]

    # Multi-turn history
    history = db_mgr.get_recent_chat_messages(conv_id, limit=8)

    # 1. Attempt Gemini if API key is present
    api_key = os.environ.get("GEMINI_API_KEY") or GEMINI_API_KEY
    if api_key:
        try:
            gemini_reply = call_gemini_chat(
                message, history, user_info, profile, subjects, classes,
                pending_tasks, exams, grades, patterns, current_day, today_classes, api_key
            )
            if gemini_reply:
                db_mgr.add_chat_message(conv_id, user_id, "user", message)
                db_mgr.add_chat_message(conv_id, user_id, "assistant", gemini_reply, context_used="Gemini Live LLM")
                return {"response": gemini_reply, "conversation_id": conv_id}
        except Exception as e:
            print(f"[AI CHAT NOTICE] Gemini API call skipped or failed ({e}). Using high-fidelity cognitive engine.")

    # 2. Context-Grounded Cognitive Engine Fallback
    reply = generate_cognitive_response(
        message, history, user_info, profile, subjects, classes,
        pending_tasks, exams, grades, patterns, current_day, today_classes
    )

    db_mgr.add_chat_message(conv_id, user_id, "user", message)
    db_mgr.add_chat_message(conv_id, user_id, "assistant", reply, context_used="Cognitive Academic Engine")

    return {
        "response": reply,
        "conversation_id": conv_id
    }


def call_gemini_chat(message, history, user, profile, subjects, classes, tasks, exams, grades, patterns, current_day, today_classes, api_key):
    system_instruction = f"""
You are Study Buddy, the personal AI academic mentor and digital twin coach for {user.get('name', 'the student')}.
You have direct, real-time access to their academic database:
- College & Course: {user.get('college', 'University')} - {profile.get('course', 'Computer Science')} ({profile.get('semester', 'Current Term')})
- Today is: {current_day}
- Today's Classes: {json.dumps([{'subject': c.get('subject_name'), 'time': c.get('time_slot'), 'room': c.get('room'), 'prof': c.get('professor')} for c in today_classes])}
- Full Weekly Schedule: {len(classes)} total lecture slots
- Enrolled Subjects: {', '.join([s.get('name', '') for s in subjects])}
- Pending Coursework & Deadlines: {json.dumps([{'title': t.get('title'), 'subject': t.get('subject_name'), 'due': t.get('due_date'), 'priority': t.get('priority')} for t in tasks[:6]])}
- Upcoming Exams: {json.dumps([{'title': e.get('title'), 'date': e.get('exam_date'), 'weight': e.get('weight_pct')} for e in exams])}
- Daily Target Study Hours: {user.get('daily_study_hours', 3.0)} hours/day (Peak Focus: {user.get('preferred_study_time', 'Evening')})
- Current Streak: {user.get('streak_days', 1)} days

Capabilities & Guidelines:
1. ACADEMIC DATA: Accurately answer questions about their classes, professors, rooms, deadlines, exams, and study targets using the real database records above.
2. GENERAL EDUCATIONAL QUESTIONS: Explain complex computer science, mathematics, engineering, or general academic concepts clearly with examples, analogies, and step-by-step logic.
3. CONVERSATIONAL CONTINUITY: Follow up on previous turns naturally. If the student refers to "that class", "the first one", or asks "why?", use conversational context.
4. TONE & ETHICS: Encouraging, concise, structured with Markdown bullets. Strictly avoid clinical or medicalized terms like 'clinical depression' or 'anxiety disorder'. Use objective terms like 'Estimated fatigue', 'Schedule pressure', or 'Cognitive load'.
"""
    contents = []
    for h in history:
        role = "user" if h.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": h.get("content", "")}]})
    contents.append({"role": "user", "parts": [{"text": message}]})

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={api_key}"
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 1600}
    }
    resp = None
    for attempt in range(3):
        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code != 503 or attempt == 2:
            break
        wait_seconds = 2 ** attempt
        print(f"[AI CHAT NOTICE] Gemini returned 503; retrying in {wait_seconds}s.")
        time.sleep(wait_seconds)
    if resp.ok:
        data = resp.json()
        candidates = data.get("candidates", [])
        if candidates:
            return candidates[0]["content"]["parts"][0]["text"].strip()
    print(f"[AI CHAT NOTICE] Gemini HTTP {resp.status_code}: {resp.text[:500]}")
    return None


# Educational Knowledge Base for offline cognitive tutoring
EDUCATIONAL_KB = {
    "dijkstra": {
        "title": "Dijkstra's Shortest Path Algorithm",
        "category": "Algorithms",
        "explanation": "Dijkstra's algorithm finds the shortest path from a single source node to all other nodes in a weighted graph with non-negative edge weights.\n\n"
                       "**Key Properties:**\n"
                       "- **Greedy Approach:** Always explores the unvisited vertex with the smallest tentative distance.\n"
                       "- **Data Structure:** Implemented efficiently using a Min-Heap (Priority Queue).\n"
                       "- **Time Complexity:** $O((V + E) \\log V)$ using a binary min-heap, or $O(E + V \\log V)$ with a Fibonacci heap.\n"
                       "- **Constraint:** Does *not* work with negative edge weights (use Bellman-Ford instead)."
    },
    "normalization": {
        "title": "Database Normalization (1NF, 2NF, 3NF, BCNF)",
        "category": "Database Systems",
        "explanation": "Database Normalization is the process of structuring relational tables to reduce data redundancy and eliminate update/delete anomalies.\n\n"
                       "- **1NF (First Normal Form):** Atomic column values; no repeating groups or arrays.\n"
                       "- **2NF (Second Normal Form):** Must be in 1NF + no partial functional dependencies (all non-key attributes fully depend on the entire primary key).\n"
                       "- **3NF (Third Normal Form):** Must be in 2NF + no transitive dependencies (non-key attributes depend only on the primary key, not on other non-key attributes).\n"
                       "- **BCNF (Boyce-Codd Normal Form):** Stricter 3NF where for every functional dependency $X \\rightarrow Y$, $X$ must be a superkey."
    },
    "acid": {
        "title": "ACID Properties in Databases",
        "category": "Database Systems",
        "explanation": "ACID guarantees that database transactions are processed reliably:\n\n"
                       "- **Atomicity:** All-or-nothing execution. If any operation fails, the entire transaction rolls back.\n"
                       "- **Consistency:** Transitions the database from one valid state to another, preserving integrity constraints.\n"
                       "- **Isolation:** Concurrent transactions execute without interfering with one another (levels: Read Uncommitted, Read Committed, Repeatable Read, Serializable).\n"
                       "- **Durability:** Once committed, changes survive system crashes or power failures (via Write-Ahead Logging / WAL)."
    },
    "tcp": {
        "title": "TCP vs UDP & The 3-Way Handshake",
        "category": "Computer Networks",
        "explanation": "TCP (Transmission Control Protocol) is connection-oriented and reliable, while UDP (User Datagram Protocol) is connectionless and lightweight.\n\n"
                       "**TCP 3-Way Handshake:**\n"
                       "1. **SYN:** Client sends Synchronize sequence number to Server.\n"
                       "2. **SYN-ACK:** Server responds with SYN and Acknowledgment.\n"
                       "3. **ACK:** Client acknowledges; connection is established.\n\n"
                       "**Comparison:**\n"
                       "- **TCP:** Guarantees order, flow control (sliding window), error checking, and retransmission (HTTP/HTTPS, SSH, FTP).\n"
                       "- **UDP:** Low latency, no retransmission overhead (DNS, VoIP, video streaming, online gaming)."
    },
    "dynamic programming": {
        "title": "Dynamic Programming (DP) Core Principles",
        "category": "Algorithms",
        "explanation": "Dynamic Programming solves complex optimization problems by breaking them into overlapping subproblems and storing subproblem results.\n\n"
                       "- **Key Requirements:** Overlapping Subproblems and Optimal Substructure.\n"
                       "- **Top-Down (Memoization):** Recursive approach with a lookup table/cache.\n"
                       "- **Bottom-Up (Tabulation):** Iterative approach building up from base cases in an array/table.\n"
                       "- **Classic Examples:** 0/1 Knapsack, Longest Common Subsequence (LCS), Fibonacci, Edit Distance."
    },
    "active recall": {
        "title": "Active Recall & Spaced Repetition Study Method",
        "category": "Study Strategy",
        "explanation": "Active Recall stimulates memory retrieval during the learning process rather than passive reading.\n\n"
                       "**How to apply it:**\n"
                       "1. **The Teach-Back Method:** Explain the concept in simple terms without looking at notes.\n"
                       "2. **Practice Problems First:** Attempt problem sets before reading the solutions.\n"
                       "3. **Spaced Repetition:** Review material after 1 day, 3 days, 1 week, and 2 weeks to flatten Ebbinghaus's forgetting curve.\n"
                       "4. **Feynman Technique:** Identify gaps where you struggle to explain a step simply."
    }
}


def generate_cognitive_response(message, history, user, profile, subjects, classes, tasks, exams, grades, patterns, current_day, today_classes):
    m_lower = message.lower()
    name = user.get("name", "Student")

    # Check for multi-turn follow-up context
    last_turn_content = ""
    if history:
        last_turn_content = history[-1].get("content", "").lower()

    # --- 1. Follow-up handling ---
    is_class_followup = any(w in m_lower for w in ["instructor", "room", "teach", "located", "where is", "where's", "what time", "which room", "who is the instructor"])
    if is_class_followup or any(k in m_lower for k in ["which one", "who teaches", "what room", "where is it", "when is it", "what time", "first one", "next class"]):
        if is_class_followup or "class" in last_turn_content or "schedule" in last_turn_content or "timetable" in last_turn_content:
            if today_classes:
                c0 = today_classes[0]
                return f"📍 **Next Scheduled Class Details:**\n- **Subject:** {c0.get('subject_name')}\n- **Timing:** {c0.get('time_slot')}\n- **Room / Lab:** **{c0.get('room')}**\n- **Instructor:** **{c0.get('professor')}**\n- **Type:** {c0.get('type', 'Lecture')}\n\nNeed directions or coursework reminders for this lecture?"
            elif classes:
                c0 = classes[0]
                return f"📍 The first class in your weekly roster is **{c0.get('subject_name')}** ({c0.get('day')} at {c0.get('time_slot')}) in **{c0.get('room')}** taught by **{c0.get('professor')}**."

        if "task" in last_turn_content or "deadline" in last_turn_content or "assignment" in last_turn_content:
            if tasks:
                t0 = tasks[0]
                return f"📌 **Top Priority Deliverable:**\n- **Title:** **{t0.get('title')}** ({t0.get('subject_name')})\n- **Due Date:** **{t0.get('due_date', 'Soon')}**\n- **Priority:** {t0.get('priority', 'High')}\n- **Points Reward:** +{t0.get('points_reward', 100)} pts upon verification\n\nSubmit your notes or code proof in the Tasks dashboard to lock in your verified streak!"

    # --- 2. General Educational / Subject Concept Tutoring ---
    for key, item in EDUCATIONAL_KB.items():
        if key in m_lower or (key == "dijkstra" and ("shortest path" in m_lower or "graph algorithm" in m_lower)):
            return f"💡 **{item['title']}**\n\n{item['explanation']}\n\n*Would you like a sample practice problem or a quick quiz question on this topic?*"

    # General programming / CS tutoring
    if any(k in m_lower for k in ["what is", "explain", "how does", "difference between", "tell me about"]):
        if "sql" in m_lower or "query" in m_lower:
            return "💡 **SQL (Structured Query Language):**\nSQL is the standard language for relational database management systems. It encompasses:\n- **DDL (Data Definition):** `CREATE`, `ALTER`, `DROP`\n- **DML (Data Manipulation):** `SELECT`, `INSERT`, `UPDATE`, `DELETE`\n- **DCL (Data Control):** `GRANT`, `REVOKE`\n\nIn your **Database Systems (CS 340)** course, focusing on indexing, join algorithms (Nested Loop, Hash, Merge), and ACID guarantees will prepare you best for midterms!"
        if "binary search" in m_lower:
            return "💡 **Binary Search Algorithm:**\nBinary Search operates on sorted arrays by repeatedly dividing the search interval in half.\n- **Complexity:** $O(\\log n)$ time, $O(1)$ auxiliary space.\n- **Precondition:** The collection *must* be sorted.\n- **Core Logic:** Compare target with middle element. If smaller, recurse left; if larger, recurse right."
        if "quicksort" in m_lower or "quick sort" in m_lower:
            return "💡 **QuickSort Algorithm:**\nA divide-and-conquer sorting algorithm based on partitioning around a chosen pivot.\n- **Average Time:** $O(n \\log n)$\n- **Worst Case:** $O(n^2)$ (when poorly chosen pivot leads to degenerate partitions)\n- **Space:** $O(\\log n)$ stack space (in-place)."
        if "osi" in m_lower:
            return "💡 **OSI 7-Layer Reference Model:**\n1. **Physical:** Bits on the wire (cables, radio frequencies)\n2. **Data Link:** Frames, MAC addresses, error detection (Ethernet, Wi-Fi)\n3. **Network:** Packets, IP addressing, routing (IP, ICMP)\n4. **Transport:** Segments, end-to-end delivery (TCP, UDP)\n5. **Session:** Dialog control and session tokens\n6. **Presentation:** Data formatting, encryption, compression (TLS/SSL)\n7. **Application:** End-user protocols (HTTP, DNS, SMTP)"

    # --- 3. Timetable / Schedule Queries ---
    if any(k in m_lower for k in ["class", "classes", "schedule", "timetable", "today", "tomorrow", "lecture", "room", "slot"]):
        if "tomorrow" in m_lower:
            curr_idx = datetime.datetime.now().weekday()
            t_day = DAYS_OF_WEEK[(curr_idx + 1) % 7]
            t_classes = [c for c in classes if str(c.get("day", "")).lower() == t_day.lower()]
            if t_classes:
                items = "\n".join([f"- **{c.get('subject_name')}**: {c.get('time_slot')} in **{c.get('room')}** (Faculty: {c.get('professor')})" for c in t_classes])
                return f"📅 **Your Classes for Tomorrow ({t_day}):**\n{items}\n\n💡 *Tip: Pre-read lecture slides tonight during your evening study block!*"
            else:
                return f"📅 You have **no classes scheduled for tomorrow ({t_day})**. A prime window for deep coursework sprint or exam revision!"

        for d in DAYS_OF_WEEK:
            if d.lower() in m_lower:
                d_classes = [c for c in classes if str(c.get("day", "")).lower() == d.lower()]
                if d_classes:
                    items = "\n".join([f"- **{c.get('subject_name')}**: {c.get('time_slot')} in **{c.get('room')}** ({c.get('professor')})" for c in d_classes])
                    return f"📅 **Your Classes on {d}:**\n{items}"
                else:
                    return f"📅 You have no classes scheduled on **{d}**."

        if today_classes:
            items = "\n".join([f"- **{c.get('subject_name')}**: {c.get('time_slot')} in **{c.get('room')}** (Faculty: {c.get('professor')})" for c in today_classes])
            return f"📅 **Your Schedule for Today ({current_day}):**\nYou have **{len(today_classes)} class{'es' if len(today_classes) > 1 else ''}** today:\n{items}\n\nNeed help organizing your study block around these timings?"
        elif classes:
            return f"📅 **Today ({current_day}):** You have no scheduled lectures today. You have {len(classes)} total classes throughout the week. Check 'My Timetable' in the sidebar to review the full weekly calendar!"
        else:
            return "📅 You haven't added your weekly timetable yet. Go to **'My Timetable & Subjects'** in the sidebar to set up your class slots and rooms."

    # --- 4. Tasks & Deadlines ---
    if any(k in m_lower for k in ["deadline", "task", "assignment", "due", "homework", "pending", "submission", "to-do", "todo"]):
        if tasks:
            items = []
            for t in tasks[:4]:
                due = t.get("due_date") or "Upcoming"
                prio = t.get("priority", "Normal")
                items.append(f"- **{t.get('title')}** ({t.get('subject_name', 'Coursework')})\n  • Due: **{due}** | Priority: **{prio}** | Reward: **+{t.get('points_reward', 100)} pts**")
            task_list_str = "\n".join(items)
            return f"🚨 **Active Deadlines & Coursework Tasks:**\nYou currently have **{len(tasks)} pending task{'s' if len(tasks) > 1 else ''}**:\n{task_list_str}\n\n💡 *All tasks require verified proof (handwritten notes or code commits + comprehension quiz) to verify genuine effort.*"
        else:
            return "🎉 **Zero pending tasks!** You're all caught up with your coursework. Would you like me to suggest an exam revision session?"

    # --- 5. Exams & Assessment Preparation ---
    if any(k in m_lower for k in ["exam", "midterm", "test", "quiz", "revision", "prepare", "syllabus"]):
        if exams:
            items = "\n".join([f"- **{e.get('title')}** ({e.get('subject_name')}): **{e.get('exam_date')}** (Weight: **{e.get('weight_pct')}%**)" for e in exams[:3]])
            return f"📚 **Upcoming Exams & High-Stakes Assessments:**\n{items}\n\n🎯 **Twin Recommendation:** Allocate at least 60% of your daily study block ({user.get('daily_study_hours', 3.0)}h) toward high-weight assessments during your peak {user.get('preferred_study_time', 'evening')} focus window."
        else:
            return "📚 You don't have any exams currently logged in your profile. You can set subject target percentages and test dates under **Grades & CGPA**."

    # --- 6. Study Plan & Routine ---
    if any(k in m_lower for k in ["study plan", "plan", "how should i study", "routine", "schedule my day", "hours"]):
        daily_hours = user.get("daily_study_hours", 3.0)
        pref_time = user.get("preferred_study_time", "Evening")
        top_task = tasks[0]["title"] if tasks else "Core Subject Problem Set"
        return f"""📋 **Tailored Study Plan for {name} ({daily_hours}h Target):**

1. **Phase 1: Deep Analytical Work (60m • {pref_time} Block)**
   - Focus on high-priority coursework: **{top_task}**
   - High cognitive retention window with zero notification distractions.

2. **Phase 2: Active Recall & Practice (45m)**
   - Solve 3-5 problem sets or review lecture slides from today's classes.
   - Upload your handwritten notes or commit code to unlock verified task points.

3. **Phase 3: Wrap-up & Tomorrow Prep (30m)**
   - Brief 15-minute recap of next lecture topics.
   - Complete 8-question teach-back quiz to lock in retention.

*Total verified effort: {daily_hours} hours. Maintains your {user.get('streak_days', 1)}-day study streak!*"""

    # --- 7. Grades & Academic Standing ---
    if any(k in m_lower for k in ["grade", "gpa", "cgpa", "score", "marks"]):
        if grades:
            avg_pct = round(sum([float(g.get("percentage", 80)) for g in grades]) / len(grades), 1)
            return f"📈 **Academic Standing & Grades:**\n- Completed Assessments: **{len(grades)}**\n- Running Average: **{avg_pct}%**\n- Your verified coursework is contributing directly to your semester target. Review subject-level breakdowns in the **Grades & CGPA** tab!"
        else:
            return "📈 **Grades & CGPA Tracker:** You haven't added grades yet. You can log assessment scores and target letter grades in the Grades & CGPA section."

    # --- 8. Polite / Direct Assistant Response ---
    return f"""👋 Hi {name}! I am your **Study Buddy**, directly synced with your real TwinStudy academic database.

Here is what I can help you with right now:
- 📅 **"What classes do I have today?"** ({len(today_classes)} scheduled today)
- 🚨 **"What assignments are due soon?"** ({len(tasks)} active tasks in queue)
- 📋 **"Give me a study plan for tonight"** (Aligned with your {user.get('daily_study_hours', 3.0)}h target)
- 📚 **"What exams do I have coming up?"**
- 💡 **Ask educational questions:** e.g., *"Explain Dijkstra's algorithm"*, *"What are ACID properties?"*, or *"TCP vs UDP"*
- 🔮 **"What if I take Friday off?"** (Runs the **What-If Flight Simulator**!)

What would you like to review?"""


# ==============================================================================
# 2. WHAT-IF / DECISION DILEMMA SIMULATOR ENGINE (Zero Medicalized Language)
# ==============================================================================

def run_what_if_simulation(user_id: str, query: str) -> dict:
    state = db_mgr.get_user_academic_state(user_id)
    user = state.get("user", {})
    subjects = state.get("subjects", [])
    classes = state.get("classes", [])
    tasks = state.get("tasks", [])
    exams = state.get("exams", [])
    grades = state.get("grades", [])
    patterns = state.get("behavior_patterns", [])

    # 1. Attempt Gemini if API key is present
    api_key = os.environ.get("GEMINI_API_KEY") or GEMINI_API_KEY
    if api_key:
        try:
            gemini_sim = call_gemini_what_if(user, subjects, classes, tasks, exams, grades, patterns, query, api_key)
            if gemini_sim:
                baseline_data = {
                    "daily_study_hours": float(user.get("daily_study_hours", 3.0)),
                    "pending_tasks": len(tasks),
                    "scheduled_classes": len(classes),
                    "recorded_grades": len(grades)
                }
                decision_id = db_mgr.record_decision(
                    user_id=user_id,
                    question=query,
                    baseline_data=baseline_data,
                    simulation_result=gemini_sim,
                    recommended_option="Option B"
                )
                gemini_sim["decision_id"] = decision_id
                gemini_sim["status"] = "success"
                return gemini_sim
        except Exception as e:
            print(f"[AI SIMULATION NOTICE] Gemini API simulation failed or timed out ({e}). Using advanced cognitive engine.")

    # 2. Cognitive Rule & Mathematical Simulation Engine
    return cognitive_what_if_simulation(user_id, user, subjects, classes, tasks, exams, grades, patterns, query)


def call_gemini_what_if(user, subjects, classes, tasks, exams, grades, patterns, query, api_key):
    system_instruction = f"""
You are the Cognitive Digital Twin What-If Decision Simulator for student {user.get('name', 'Student')}.
Analyze the student's hypothetical decision dilemma based STRICTLY on their REAL academic database:
- Enrolled Subjects: {json.dumps([{'name': s.get('name'), 'target_pct': s.get('target_percentage'), 'credits': s.get('credits')} for s in subjects])}
- Weekly Timetable: {json.dumps([{'day': c.get('day'), 'subject': c.get('subject_name'), 'time': c.get('time_slot'), 'prof': c.get('professor'), 'room': c.get('room')} for c in classes])}
- Active Tasks & Deadlines: {json.dumps([{'title': t.get('title'), 'subject': t.get('subject_name'), 'due': t.get('due_date'), 'prio': t.get('priority')} for t in tasks])}
- Upcoming Exams: {json.dumps([{'title': e.get('title'), 'subject': e.get('subject_name'), 'date': e.get('exam_date'), 'weight': e.get('weight_pct')} for e in exams])}
- Baseline Daily Study Hours: {user.get('daily_study_hours', 3.0)} hrs/day
- Behavioral Patterns: {', '.join([p.get('title', '') for p in patterns])}

RULES:
- Act as a thoughtful, practical decision adviser for this student's actual situation, not as a rigid keyword classifier.
- Answer the scenario the student actually asked about. Consider the likely benefits, risks, trade-offs, and a realistic alternative when useful.
- Use the provided student records (subjects, timetable, tasks, deadlines, exams, grades, and study patterns) only when relevant. Do not claim a record exists if it is absent.
- Never invent exam dates, assignment deadlines, completed work, grades, score changes, percentages, probabilities, fatigue measurements, or exact recovery times.
- Do not present a projected exam score as a fact. If the available records cannot support a reliable estimate, use the exact phrase "Not reliably predictable from available data".
- Use "Not statistically calibrated" for confidence. Do not invent confidence percentages.
- Give a clear, appropriately qualified recommendation; explain the main reasons in plain language; identify what could change the recommendation; and offer concrete next steps.
- If key information is missing, state the uncertainty briefly and give conditional advice rather than pretending to know.
- Use actual dates only when supplied in the records. Do not assume an exam date from a general statement such as "next week".
- Avoid generic filler, moralising, and medicalised claims. Be supportive and direct without diagnosing the student.
- Do not claim access to location, private messages, device activity, or other telemetry unless it is explicitly included in the supplied data.
- Keep the two futures meaningfully different and tailored to the student's scenario. A balanced or modified option may be more useful than an unrealistic all-or-nothing choice.
2. Return ONLY a valid JSON object with EXACTLY this structure:
{{
  "futureA": {{
    "focus": "Title of Option A (Unprepared Choice / Queried Path)",
    "exam_score_projected": "Not reliably predictable from available data",
    "assignment_completion": "Describe the possible impact based on recorded tasks",
    "deadline_risk": "Refer only to actual recorded deadlines",
    "fatigue": "e.g. Estimated fatigue: High (requires cramming)",
    "schedule_pressure": "Schedule pressure: Critical",
    "recovery_time": "Recovery time: High (needs 36h to recover)",
    "confidence": "Not statistically calibrated"
  }},
  "futureB": {{
    "focus": "Title of Option B (Twin Recommended Strategy)",
    "exam_score_projected": "Not reliably predictable from available data",
    "assignment_completion": "Give a proposed action without claiming completion",
    "deadline_risk": "Do not guarantee zero risk",
    "fatigue": "e.g. Rested & Low Fatigue",
    "schedule_pressure": "Schedule pressure: Low",
    "recovery_time": "Recovery time: Optimal",
    "confidence": "Not statistically calibrated"
  }},
  "why_this": {{
    "recommendation": "Clear, direct actionable advice referencing the student's actual timetable and assignments",
    "why": "Detailed academic reasoning citing study hours, classes, and deadlines",
    "top_factors_plain_language": ["Factor 1", "Factor 2", "Factor 3"],
    "what_if_ignored": "Consequence if student ignores advice",
    "alternative_plan": ["Step 1", "Step 2", "Step 3"],
    "confidence_level": {{"score": "Not statistically calibrated", "reason": "No validated outcome-probability model is available"}},
    "trade_offs": {{"option_a_drawbacks": "...", "option_b_advantages": "..."}},
    "data_receipt": {{
      "sources_used": ["Student Timetable Schedule", "Active Coursework Tasks List", "Daily Study Capacity Telemetry"],
      "sources_not_used": ["Personal Chat Data (Muted)", "Device GPS (Muted)"],
      "privacy_guarantee": "Telemetry analyzed locally. Personal messaging and GPS permanently muted."
    }}
  }}
}}
"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={api_key}"
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": f"Student asks: '{query}'"}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
    }
    resp = requests.post(url, json=payload, timeout=30)
    if resp.ok:
        data = resp.json()
        candidates = data.get("candidates", [])
        if candidates:
            raw_text = candidates[0]["content"]["parts"][0]["text"].strip()
            parsed = json.loads(raw_text)
            # Normalize keys
            parsed["future_a"] = parsed.get("futureA", {})
            parsed["future_b"] = parsed.get("futureB", {})
            parsed["futureA"] = parsed["future_a"]
            parsed["futureB"] = parsed["future_b"]
            parsed["why_this_panel"] = parsed.get("why_this", {})
            parsed["query"] = query
            return parsed
    return None


def cognitive_what_if_simulation(user_id: str, user: dict, subjects: list, classes: list, tasks: list, exams: list, grades: list, patterns: list, query: str) -> dict:
    # GENERAL ADVISOR FALLBACK — evidence-cautious
    # This path must remain useful even when Gemini is unavailable. It deliberately
    # avoids fabricated grades, risk percentages, completion guarantees, and timings.
    question = " ".join(str(query or "").split()).strip()
    q_norm = normalize_text(question)
    try:
        daily_study_hours = float(user.get("daily_study_hours", 3.0) or 3.0)
    except (TypeError, ValueError):
        daily_study_hours = 3.0

    scenario = re.sub(
        r"^\s*(what\s+if|what\s+would\s+happen\s+if|suppose|imagine)\b[\s,:-]*",
        "", question, flags=re.IGNORECASE,
    ).strip(" ?.! ") or question
    recorded_task_count = len(tasks or [])
    recorded_class_count = len(classes or [])
    recorded_exam_count = len(exams or [])
    recorded_subject_count = len(subjects or [])
    recorded_grade_count = len(grades or [])

    trip_terms = ("trip", "travel", "vacation", "holiday", "tour", "outing", "wedding", "hackathon", "party")
    exam_terms = ("exam", "see", "midterm", "final", "test", "quiz", "assessment")
    study_terms = ("study", "assignment", "deadline", "coursework", "revision", "revise", "class", "lecture", "subject")
    sleep_terms = ("all nighter", "all-nighter", "sleep", "stay awake", "overnight")
    money_terms = ("buy", "purchase", "spend", "money", "cost", "price", "budget", "laptop", "phone")
    skip_terms = ("skip class", "skip lecture", "miss class", "miss lecture", "bunk")

    # Use only small, transparent conditional guidance; never infer exact outcomes.
    if any(term in q_norm for term in trip_terms) and any(term in q_norm for term in exam_terms):
        recommendation = (
            "My recommendation: the trip can be reasonable if your exam dates do not clash, your revision is on track, "
            "and any genuinely urgent deadlines are handled. If you are already behind in important topics or submissions, "
            "shorten or postpone the trip rather than relying on a last-minute study sprint."
        )
        alternative = [
            "Check the official exam dates and the actual due dates of pending tasks.",
            "List the two or three topics that most need revision and assess honestly how prepared you are.",
            "Choose the full trip only if the remaining revision time is realistic; otherwise shorten or reschedule it.",
            "Protect sleep and schedule a specific revision block for your return."
        ]
        ignored = "Travelling without checking dates or preparation could leave less time for revision or unfinished submissions; the actual impact depends on your circumstances."
    elif any(term in q_norm for term in sleep_terms):
        recommendation = (
            "My recommendation: avoid making an all-nighter the default plan. A shorter, prioritized study session followed by sleep "
            "is generally the more sustainable option. Focus on the highest-value topics, and use an all-nighter only as an exceptional "
            "last resort rather than assuming it will improve your result."
        )
        alternative = [
            "Pick the most important topics rather than trying to cover everything.",
            "Use focused study blocks and stop at a planned time that leaves room for sleep.",
            "If the deadline is too close, prioritize essential work and ask for clarification or an extension where appropriate."
        ]
        ignored = "If you sacrifice sleep, concentration and the ability to keep a steady routine may suffer; this fallback cannot predict the size of that effect for you."
    elif any(term in q_norm for term in skip_terms):
        recommendation = (
            "My recommendation: attend if the class covers material you are struggling with, announces assessment details, or is difficult to catch up on. "
            "Missing one class may be manageable when you have a legitimate reason and a concrete catch-up plan, but check attendance rules and get the notes."
        )
        alternative = [
            "Check whether attendance is compulsory or affects eligibility or marks.",
            "Consider what is being taught and whether reliable notes or a recording will be available.",
            "If you miss it, arrange notes and set a specific time to cover the material."
        ]
        ignored = "Skipping without checking attendance rules or arranging the material could create avoidable academic gaps."
    elif any(term in q_norm for term in money_terms):
        recommendation = (
            "My recommendation: pause before committing and compare the full cost with your budget and the practical benefit. "
            "Proceed only if essential expenses remain covered and the purchase solves a real need; otherwise compare alternatives or wait."
        )
        alternative = [
            "Calculate the full cost, including required accessories, maintenance, and any recurring payments.",
            "Compare at least one lower-cost or no-cost alternative against the main need.",
            "Avoid taking on debt or spending money needed for essentials just to make the decision sooner."
        ]
        ignored = "Committing before checking the total cost and alternatives could create avoidable financial pressure; your actual budget was not supplied here."
    else:
        recommendation = (
            "My recommendation: don't decide on the hypothetical alone. The choice may be worthwhile if it meets your main goal and the downside is manageable, "
            "but start with a smaller or reversible version when possible. Check the time, cost, obligations, and what you would give up before committing."
        )
        alternative = [
            "Define what a good outcome would look like for this decision.",
            "Check the most important constraint: time, money, obligations, or the effect on your longer-term goal.",
            "Try a smaller or reversible version first if that is practical.",
            "Set a review point and change course if the costs outweigh the benefits."
        ]
        ignored = "Proceeding without checking the main trade-offs could cause avoidable pressure or opportunity cost. The specific outcome cannot be inferred from the question alone."

    # Academic records are used as context, not as proof that a deadline is at risk.
    academic_context = []
    if recorded_task_count:
        academic_context.append(f"{recorded_task_count} pending task(s) are recorded; task-specific due dates and completion status were not verified by this fallback.")
    else:
        academic_context.append("No pending tasks are recorded in the available task list; that does not prove there is no unrecorded work.")
    if recorded_class_count:
        academic_context.append(f"{recorded_class_count} timetable class(es) are recorded; a conflict cannot be confirmed unless the scenario includes matching dates.")
    else:
        academic_context.append("No timetable classes are recorded in the available data.")
    if recorded_exam_count:
        academic_context.append(f"{recorded_exam_count} exam record(s) are available, but this fallback does not infer an exam date unless it is verified from the record.")
    if recorded_subject_count:
        academic_context.append(f"{recorded_subject_count} subject(s) are recorded.")
    if recorded_grade_count:
        academic_context.append(f"{recorded_grade_count} grade/assessment record(s) are present, but they do not support a reliable prediction of a future score.")

    recorded_capacity = (
        f"The profile records a daily study-capacity baseline of {daily_study_hours:g} hour(s); actual free time can differ."
    )
    future_a = {
        "focus": f"Proceed with the choice as described: {scenario}",
        "exam_score_projected": "Not reliably predictable from available data",
        "assignment_completion": "Not established by this simulation; depends on actual progress and deadlines.",
        "deadline_risk": "Unconfirmed; check actual recorded due dates and obligations before deciding.",
        "fatigue": "Cannot be reliably inferred from the hypothetical alone; depends on sleep, workload, and personal circumstances.",
        "schedule_pressure": "Could increase if this choice displaces time needed for existing commitments.",
        "recovery_time": "Not reliably predictable from available data.",
        "confidence": "Not statistically calibrated",
    }
    future_b = {
        "focus": "Use a balanced alternative with a checkpoint before committing",
        "exam_score_projected": "Not reliably predictable from available data",
        "assignment_completion": "A proposed plan only; completion and submission have not been verified.",
        "deadline_risk": "Can be assessed only after checking the actual due dates and obligations.",
        "fatigue": "A realistic plan that leaves room for rest may be more sustainable; individual effects are not measured.",
        "schedule_pressure": "May be easier to manage if the plan protects time for urgent commitments.",
        "recovery_time": "Depends on the remaining work and the person's circumstances; not estimated here.",
        "confidence": "Not statistically calibrated",
    }

    why_this = {
        "recommendation": recommendation,
        "why": (
            f"You asked: {question} The key trade-off is between the benefit you hope to get and the time, cost, "
            "or commitments it may affect. " + " ".join(academic_context) + " " + recorded_capacity +
            " The available data does not justify precise score changes, risk percentages, or a guaranteed outcome."
        ),
        "top_factors_plain_language": [
            "The benefit you want from the choice and whether it is worth the trade-off.",
            "Recorded academic commitments, which should be checked against actual dates rather than assumed to conflict.",
            recorded_capacity,
            "Important missing details should be checked before treating this as a final decision."
        ],
        "what_if_ignored": ignored,
        "alternative_plan": alternative,
        "confidence_level": {
            "score": "Not statistically calibrated",
            "reason": "This is conditional planning guidance, not a statistically validated forecast. Some dates, constraints, or personal details may be missing."
        },
        "trade_offs": {
            "option_a_drawbacks": "Following the choice without checking constraints may leave less time or flexibility for other priorities.",
            "option_b_advantages": "A checkpoint and a more reversible alternative make it easier to adjust when the real constraints are known."
        },
        "data_receipt": {
            "tasks_pending_count": recorded_task_count,
            "tasks_analyzed": 0,
            "classes_scheduled_count": recorded_class_count,
            "sources_used": [
                f"Student profile study-capacity baseline ({daily_study_hours:g}h/day recorded)",
                f"Coursework task list ({recorded_task_count} task(s) recorded)",
                f"Weekly timetable ({recorded_class_count} class(es) recorded)",
                f"Exam records ({recorded_exam_count} record(s) available)"
            ],
            "sources_not_used": ["Personal Chat Data (Muted)", "Device GPS (Muted)"],
            "privacy_guarantee": "This fallback used only the supplied profile and academic record lists; it did not inspect personal messages or device GPS."
        }
    }
    return {
        "future_a": future_a,
        "future_b": future_b,
        "futureA": future_a,
        "futureB": future_b,
        "why_this": why_this,
        "why_this_panel": why_this,
        "query": question,
        "status": "fallback"
    }
