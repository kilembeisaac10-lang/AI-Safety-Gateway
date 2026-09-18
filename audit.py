import hashlib
import hmac
import json
import os
import time

from gateway_secrets import AI_AUDIT_SECRET


class AuditLog:

    def __init__(self, log_file="audit.jsonl", secret=None):

        if secret is None:
            secret = AI_AUDIT_SECRET

        if not isinstance(secret, str):
            raise TypeError("Secret must be a string")

        if len(secret) < 32:
            raise ValueError("Audit secret is too weak")

        self.log_file = log_file
        self.secret = secret.encode("utf-8")

    def _sign(self, content):
        return hmac.new(
            self.secret,
            content.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def append(self, event):

        if not isinstance(event, dict):
            raise TypeError("Event must be a dictionary")

        previous_hash = "GENESIS"

        if os.path.exists(self.log_file):

            with open(
                self.log_file,
                "r",
                encoding="utf-8"
            ) as file:

                lines = file.readlines()

            if lines:
                last = json.loads(lines[-1])
                previous_hash = last["hash"]

        record = {
            "timestamp": int(time.time()),
            "event": event,
            "previous_hash": previous_hash,
        }

        content = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":")
        )

        record["hash"] = self._sign(content)

        with open(
            self.log_file,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(record) + "\n"
            )

    def verify(self):

        if not os.path.exists(self.log_file):
            return True

        previous_hash = "GENESIS"

        with open(
            self.log_file,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                record = json.loads(line)

                saved_hash = record.pop("hash")

                if record["previous_hash"] != previous_hash:
                    return False

                content = json.dumps(
                    record,
                    sort_keys=True,
                    separators=(",", ":")
                )

                expected_hash = self._sign(content)

                if not hmac.compare_digest(
                    saved_hash,
                    expected_hash
                ):
                    return False

                previous_hash = saved_hash

        return True


if __name__ == "__main__":

    audit = AuditLog("test_audit.jsonl")

    audit.append({
        "action": "demo/read",
        "decision": "ALLOW"
    })

    audit.append({
        "action": "demo/delete",
        "decision": "BLOCKED"
    })

    print(
        "Audit valide :",
        audit.verify()
    )