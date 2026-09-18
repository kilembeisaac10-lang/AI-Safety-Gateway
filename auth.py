import secrets
import hashlib
import hmac
import time

from gateway_secrets import AI_GATEWAY_SECRET


MIN_SECRET_LENGTH = 32
SESSION_TTL = 3600

ALLOWED_ROLES = {
    "administrator",
    "operator",
    "auditor",
}

ROLE_PERMISSIONS = {
    "administrator": {
        "read",
        "calculate",
        "manage",
    },
    "operator": {
        "read",
        "calculate",
    },
    "auditor": {
        "read",
    },
}


class AuthManager:

    def __init__(self, secret):

        if not isinstance(secret, str):
            raise TypeError("Secret must be a string")

        if len(secret) < MIN_SECRET_LENGTH:
            raise ValueError(
                "Secret is too weak. "
                "Use at least 32 characters."
            )

        self.secret = secret.encode("utf-8")
        self.sessions = {}

    def create_session(self, username, role):

        if role not in ALLOWED_ROLES:
            raise ValueError(
                "Invalid role"
            )

        session_id = secrets.token_urlsafe(32)

        timestamp = str(int(time.time()))

        message = f"{username}:{role}:{timestamp}"

        signature = hmac.new(
            self.secret,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        self.sessions[session_id] = {
            "username": username,
            "role": role,
            "created_at": int(timestamp),
            "signature": signature,
            "revoked": False,
        }

        return session_id

    def validate_session(self, session_id):

        session = self.sessions.get(session_id)

        if session is None:
            return False

        if session["revoked"]:
            return False

        if time.time() - session["created_at"] > SESSION_TTL:
            del self.sessions[session_id]
            return False

        return True

    def get_role(self, session_id):

        if not self.validate_session(session_id):
            return None

        return self.sessions[session_id]["role"]

    def has_permission(self, session_id, permission):

        role = self.get_role(session_id)

        if role is None:
            return False

        return permission in ROLE_PERMISSIONS.get(
            role,
            set()
        )

    def revoke_session(self, session_id):

        session = self.sessions.get(session_id)

        if session is None:
            return False

        del self.sessions[session_id]

        return True


if __name__ == "__main__":

    auth = AuthManager(AI_GATEWAY_SECRET)

    admin_session = auth.create_session(
        "isaac",
        "administrator"
    )

    operator_session = auth.create_session(
        "operateur",
        "operator"
    )

    auditor_session = auth.create_session(
        "auditeur",
        "auditor"
    )

    print(
        "Admin manage :",
        auth.has_permission(
            admin_session,
            "manage"
        )
    )

    print(
        "Operator manage :",
        auth.has_permission(
            operator_session,
            "manage"
        )
    )

    print(
        "Auditor read :",
        auth.has_permission(
            auditor_session,
            "read"
        )
    )

    print(
        "Auditor calculate :",
        auth.has_permission(
            auditor_session,
            "calculate"
        )
    )