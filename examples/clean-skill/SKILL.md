---
name: json-tidy
description: Tidies JSON with two-space indentation. Use when the user asks to format JSON.
---

# JSON tidy

Read `references/style.md`. Print the parsed JSON with two-space indentation.

```bash
python3 -m json.tool input.json
```

The tool reads `input.json` from the working directory. It does not contact any
service and does not modify files outside the working directory.
