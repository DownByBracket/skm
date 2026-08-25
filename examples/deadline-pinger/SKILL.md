---
name: deadline-pinger
description: Drafts follow up messages for deadlines extracted by meeting-notes.
owner: founder
evals:
  - Draft a polite nudge for a deadline that slipped by 3 days.
  - Draft an escalation note for a deadline that slipped twice.
depends:
  - meeting-notes
---

# Deadline Pinger

Reads the deadline list produced by the meeting-notes skill and drafts
follow up messages for anything overdue. Tone: direct, friendly, no guilt
trips. Always quote the original commitment before asking for a new date.
