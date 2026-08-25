---
name: meeting-notes
description: Turns raw meeting transcripts into decisions, owners, and deadlines.
owner: founder
evals:
  - Summarize a 30 minute standup transcript into 3 decisions with owners.
  - Extract deadlines from a sales call transcript and flag missing dates.
  - Handle a transcript where two speakers talk over each other.
depends: []
---

# Meeting Notes

Use this skill when the user pastes a raw meeting transcript and wants a
clean record of what was decided.

## Process

1. Split the transcript into speaking turns.
2. Extract decisions, each with a named owner. If no owner was stated,
   mark it UNASSIGNED, never guess.
3. Extract deadlines as ISO dates. If a deadline is vague ("next week"),
   keep the original phrasing and flag it.
4. Close with a three line summary: what changed, who is on the hook,
   what is still open.

## Output format

Decisions first, then deadlines, then open questions. No preamble. Keep it under 200 words.
