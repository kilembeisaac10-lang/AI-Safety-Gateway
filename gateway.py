from policy import evaluate_action
from auth import AuthManager
from emergency_stop import EmergencyStop
from audit import AuditLog

from gateway_secrets import (
    AI_GATEWAY_SECRET,
    AI_AUDIT_SECRET
)


class SafetyGateway:

    def __init__(self):

        self.auth = AuthManager(
            AI_GATEWAY_SECRET
        )

        self.stop = EmergencyStop(
            "emergency_stop.json"
        )

        self.audit = AuditLog(
            "audit.jsonl",
            AI_AUDIT_SECRET
        )

    def create_session(self, username, role):

        return self.auth.create_session(
            username,
            role
        )

    def _get_actor(self, session_id):

        if not self.auth.validate_session(
            session_id
        ):
            return {
                "username": "unknown",
                "role": "unknown"
            }

        session = self.auth.sessions.get(
            session_id
        )

        if session is None:
            return {
                "username": "unknown",
                "role": "unknown"
            }

        return {
            "username": session["username"],
            "role": session["role"]
        }

    def evaluate(
        self,
        session_id,
        tool,
        operation,
        args=None
    ):

        actor = self._get_actor(
            session_id
        )

        if not self.auth.validate_session(
            session_id
        ):

            result = {
                "decision": "BLOCKED",
                "reason": "Invalid or expired session"
            }

            self.audit.append({
                "username": actor["username"],
                "role": actor["role"],
                "action": f"{tool}/{operation}",
                "decision": "BLOCKED",
                "reason": "Invalid or expired session"
            })

            return result

        if self.stop.is_stopped():

            result = {
                "decision": "BLOCKED",
                "reason": "Emergency stop is active"
            }

            self.audit.append({
                "username": actor["username"],
                "role": actor["role"],
                "action": f"{tool}/{operation}",
                "decision": "BLOCKED",
                "reason": "Emergency stop"
            })

            return result

        if not self.auth.has_permission(
            session_id,
            operation
        ):

            result = {
                "decision": "BLOCKED",
                "reason": "Role does not have permission"
            }

            self.audit.append({
                "username": actor["username"],
                "role": actor["role"],
                "action": f"{tool}/{operation}",
                "decision": "BLOCKED",
                "reason": "Role does not have permission"
            })

            return result

        result = evaluate_action(
            tool,
            operation,
            args
        )

        self.audit.append({
            "username": actor["username"],
            "role": actor["role"],
            "action": f"{tool}/{operation}",
            "decision": result["decision"],
            "reason": result["reason"]
        })

        return result


if __name__ == "__main__":

    gateway = SafetyGateway()

    admin_session = gateway.create_session(
        "isaac",
        "administrator"
    )

    operator_session = gateway.create_session(
        "operator",
        "operator"
    )

    auditor_session = gateway.create_session(
        "auditor",
        "auditor"
    )

    gateway.stop.set_stop(False)

    print(
        "Admin read :",
        gateway.evaluate(
            admin_session,
            "demo",
            "read",
            {}
        )
    )

    print(
        "Operator calculate :",
        gateway.evaluate(
            operator_session,
            "demo",
            "calculate",
            {}
        )
    )

    print(
        "Auditor calculate :",
        gateway.evaluate(
            auditor_session,
            "demo",
            "calculate",
            {}
        )
    )

    gateway.stop.set_stop(True)

    print(
        "Emergency stop :",
        gateway.evaluate(
            admin_session,
            "demo",
            "read",
            {}
        )
    )