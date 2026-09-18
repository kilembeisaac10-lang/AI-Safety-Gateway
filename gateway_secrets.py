import os

AI_GATEWAY_SECRET = os.environ.get("AI_GATEWAY_SECRET")
AI_AUDIT_SECRET = os.environ.get("AI_AUDIT_SECRET")

if not AI_GATEWAY_SECRET or not AI_AUDIT_SECRET:
    raise RuntimeError(
        "Les secrets AI_GATEWAY_SECRET et AI_AUDIT_SECRET "
        "doivent être configurés dans l'environnement."
    )