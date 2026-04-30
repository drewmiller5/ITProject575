import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER REFERENCES users(id),
            credential_id TEXT UNIQUE NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS login_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            timestamp   TEXT DEFAULT (datetime('now')),
            ip_address  TEXT,
            user_agent  TEXT,
            risk_score  REAL,
            outcome     TEXT
        );

        CREATE TABLE IF NOT EXISTS security_questions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            question    TEXT NOT NULL,
            answer      TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        );
        """)
    print("Database initialized OK")

def create_user(username):
    with get_db() as db:
        try:
            db.execute("INSERT INTO users (username) VALUES (?)", (username,))
            db.commit()
            print(f"User {username} created")
            return True
        except sqlite3.IntegrityError:
            print(f"Username {username} already exists")
            return False

def get_user(username):
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return user

def save_credential(user_id, credential_id):
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO credentials (user_id, credential_id) VALUES (?, ?)",
                (user_id, credential_id)
            )
            db.commit()
            print(f"Credential saved for user_id {user_id}")
            return True
        except sqlite3.IntegrityError:
            print(f"Credential already exists")
            return False

def get_credential(credential_id):
    with get_db() as db:
        cred = db.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
        return cred

def get_credentials_by_user(user_id):
    with get_db() as db:
        creds = db.execute(
            "SELECT * FROM credentials WHERE user_id = ?", (user_id,)
        ).fetchall()
        return creds

def log_login_event(user_id, ip_address, user_agent, risk_score, outcome):
    with get_db() as db:
        db.execute(
            """INSERT INTO login_events (user_id, ip_address, user_agent, risk_score, outcome)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, ip_address, user_agent, risk_score, outcome)
        )
        db.commit()
        print(f"Login event logged - outcome: {outcome}, risk: {risk_score}")

def get_login_history(user_id):
    with get_db() as db:
        events = db.execute(
            """SELECT * FROM login_events
               WHERE user_id = ?
               ORDER BY timestamp DESC LIMIT 10""",
            (user_id,)
        ).fetchall()
        return events

def save_security_questions(user_id, questions_and_answers):
    with get_db() as db:
        for question, answer in questions_and_answers:
            db.execute(
                "INSERT INTO security_questions (user_id, question, answer) VALUES (?, ?, ?)",
                (user_id, question, answer.strip().lower())
            )
        db.commit()
        print(f"Security questions saved for user_id {user_id}")

def get_security_questions(user_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        return rows

def verify_security_answers(user_id, answers):
    with get_db() as db:
        rows = db.execute(
            "SELECT question, answer FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        if not rows:
            return False
        stored = {row["question"]: row["answer"] for row in rows}
        for question, answer in answers:
            if stored.get(question) != answer.strip().lower():
                return False
        return True

def normalize_answer(answer):
    """Normalize answers so number words match digits and vice versa."""
    word_to_num = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3',
        'four': '4', 'five': '5', 'six': '6', 'seven': '7',
        'eight': '8', 'nine': '9', 'ten': '10'
    }
    num_to_word = {v: k for k, v in word_to_num.items()}
    cleaned = answer.strip().lower()
    if cleaned in word_to_num:
        return word_to_num[cleaned]
    if cleaned in num_to_word:
        return num_to_word[cleaned]
    return cleaned

def verify_security_answers(user_id, answers):
    with get_db() as db:
        rows = db.execute(
            "SELECT question, answer FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        if not rows:
            return False
        stored = {row["question"]: row["answer"] for row in rows}
        for question, answer in answers:
            stored_answer = stored.get(question, "")
            submitted = normalize_answer(answer)
            expected = normalize_answer(stored_answer)
            if submitted != expected:
                return False
        return True
    
if __name__ == "__main__":
    init_db()