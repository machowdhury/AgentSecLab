# Splunk Web login without exposing the credential

Do this **before the participant arrives**, once per browser profile (Splunk's own session may lapse; re-check each session). The participant never needs the password.

1. In the terminal, from the repository root, copy the password straight to the clipboard. This prints nothing:
   ```
   awk -F= '/^SPLUNK_PASSWORD=/{sub(/^[^=]*=/,""); gsub(/^["'"'"']|["'"'"']$/,""); printf "%s",$0}' .env | pbcopy
   ```
2. In the participant's browser profile open `http://127.0.0.1:8000/en-US/app/agentsec/ws_lab_loandesk_001`. Username: the lab admin (`admin` unless you changed it in `.env`). Paste the password into the field with Cmd+V.
3. **Clear the clipboard immediately**: `pbcopy </dev/null`
4. Confirm the Loan Desk view loads with no login prompt. Do not tick any "remember" prompt from a password manager that would store it in the participant's profile.

Rules
- Never `cat`, `echo` or `grep` the value, never paste it into chat, a ticket, a URL, a lab page, or the observation log, and never do this while a participant, recording or screen share can see it.
- Never type it in the terminal as an argument (shell history). The `.env` file stays mode 600 and is never committed.
- If the session lapses mid-session, ask the participant to step away, repeat steps 1 to 4, then continue. Log it as a Tier 0 intervention.
- Tested on this Mac: the copy yields a non-empty value, is never displayed, and the clipboard is empty after step 3. Pasting into the real Splunk login form was not exercised by a person.
