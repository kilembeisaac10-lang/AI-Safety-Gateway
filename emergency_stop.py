import json
import os
import tempfile
import threading


class EmergencyStop:

    def __init__(self, state_file="emergency_stop.json"):
        self.state_file = state_file
        self.lock = threading.Lock()

    def _read_state(self):
        if not os.path.exists(self.state_file):
            # Fail-closed : état inconnu = STOP
            return True

        try:
            with open(self.state_file, "r", encoding="utf-8") as file:
                data = json.load(file)

            if not isinstance(data, dict):
                return True

            if not isinstance(data.get("stopped"), bool):
                return True

            return data["stopped"]

        except Exception:
            # Fichier corrompu ou illisible = STOP
            return True

    def is_stopped(self):
        with self.lock:
            return self._read_state()

    def set_stop(self, enabled):
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")

        data = {
            "stopped": enabled
        }

        directory = os.path.dirname(
            os.path.abspath(self.state_file)
        )

        os.makedirs(directory, exist_ok=True)

        with self.lock:
            fd, temporary_file = tempfile.mkstemp(
                dir=directory,
                prefix=".emergency_",
                text=True
            )

            try:
                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8"
                ) as file:

                    json.dump(data, file)
                    file.flush()
                    os.fsync(file.fileno())

                os.replace(
                    temporary_file,
                    self.state_file
                )

            except Exception:
                try:
                    os.unlink(temporary_file)
                except OSError:
                    pass

                raise


if __name__ == "__main__":

    stop = EmergencyStop()

    print("État initial :", stop.is_stopped())

    stop.set_stop(False)

    print("Après désactivation :", stop.is_stopped())

    stop.set_stop(True)

    print("Après activation :", stop.is_stopped())