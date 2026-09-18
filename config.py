import os


MIN_SECRET_LENGTH = 32


def get_secret(name):
    value = os.environ.get(name)

    if value is None:
        raise ValueError(
            f"Secret manquant : {name}"
        )

    if not isinstance(value, str):
        raise TypeError(
            f"Secret invalide : {name}"
        )

    if len(value) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"Secret trop court : {name}"
        )

    return value