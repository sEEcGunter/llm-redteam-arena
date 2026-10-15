"""
HTTP client that attacks the NovaTech webapp at localhost:5000.
Uses a persistent requests.Session so auth cookies survive across calls.
"""
import requests

WEBAPP_URL = "http://localhost:5000"

# Shared session — preserves cookies (auth state) between calls
_session = requests.Session()


def chat(message: str, history: list[dict] | None = None, customer_id: str = "") -> dict:
    """Returns {"response": str, "actions": list}.
    Pass customer_id to simulate portal session (T-11 IDOR — no auth check server-side).
    """
    r = _session.post(
        f"{WEBAPP_URL}/chat",
        json={"message": message, "history": history or [], "customer_id": customer_id},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()


def summarize(document: str) -> str:
    r = _session.post(
        f"{WEBAPP_URL}/summarize",
        json={"document": document},
        timeout=120,
    )
    r.raise_for_status()
    return r.json().get("response", "")


def ask(question: str) -> str:
    r = _session.post(
        f"{WEBAPP_URL}/ask",
        json={"question": question},
        timeout=120,
    )
    r.raise_for_status()
    return r.json().get("response", "")


def ingest(doc_id: str, content: str, metadata: dict | None = None) -> bool:
    r = _session.post(
        f"{WEBAPP_URL}/ingest",
        json={"id": doc_id, "content": content, "metadata": metadata or {}},
        timeout=30,
    )
    return r.ok


def submit_feedback(text: str) -> bool:
    r = _session.post(
        f"{WEBAPP_URL}/feedback",
        json={"text": text},
        timeout=30,
    )
    return r.ok


def login(username: str = "admin", password: str = "novatech2024") -> bool:
    r = _session.post(
        f"{WEBAPP_URL}/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    return r.ok and r.json().get("success", False)


def logout() -> None:
    _session.post(f"{WEBAPP_URL}/logout", timeout=10)


def admin_feedbacks() -> list[dict]:
    r = _session.get(f"{WEBAPP_URL}/admin/feedbacks", timeout=30)
    r.raise_for_status()
    return r.json().get("feedbacks", [])


def compose(instructions: str, context: str = "") -> str:
    r = _session.post(
        f"{WEBAPP_URL}/compose",
        json={"instructions": instructions, "context": context},
        timeout=120,
    )
    r.raise_for_status()
    return r.json().get("response", "")


def capture(data: dict | None = None) -> dict:
    """GET returns capture log. POST adds an entry."""
    if data:
        r = _session.post(f"{WEBAPP_URL}/capture", json=data, timeout=10)
    else:
        r = _session.get(f"{WEBAPP_URL}/capture", timeout=10)
    r.raise_for_status()
    return r.json()


def admin_summarize() -> dict:
    """Returns {"response": str, "actions": list}."""
    r = _session.post(f"{WEBAPP_URL}/admin/summarize", timeout=120)
    r.raise_for_status()
    return r.json()


def admin_actions() -> list[dict]:
    r = _session.get(f"{WEBAPP_URL}/admin/actions", timeout=10)
    r.raise_for_status()
    return r.json().get("actions", [])


def search(question: str) -> dict:
    """T-09 — SQL injection via LLM output. Returns {"sql": str, "results": list, "count": int}."""
    r = _session.post(
        f"{WEBAPP_URL}/search",
        json={"question": question},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()


def api_customers(api_key: str, page: int = 1, limit: int = 5) -> dict:
    """T-04 impact validation — call /api/v2/customers with the extracted Nova API key.
    Without key returns 401. With correct key returns paginated customer records.
    """
    r = _session.get(
        f"{WEBAPP_URL}/api/v2/customers",
        headers={"X-Nova-Key": api_key},
        params={"page": page, "limit": limit},
        timeout=30,
    )
    return r.json()


def is_available() -> bool:
    try:
        _session.get(f"{WEBAPP_URL}/health", timeout=5).raise_for_status()
        return True
    except Exception:
        return False
