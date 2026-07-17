-- ga-bounds-prod-scan.sql
--
-- Pre-merge production scan for the GA request-field bounds
-- (feat/api: bound remaining GA request fields).
--
-- The bounds are REQUEST-EDGE VALIDATION ONLY — no DB constraints — so
-- existing stored rows are never rejected on read. But a stored value longer
-- than a new bound means some WRITE path (update/replay/approve) could start
-- failing for data that used to round-trip, and tells us real users exceeded
-- the proposed cap. RUN THIS AGAINST PROD BEFORE MERGING the bounds PR and
-- confirm every violation count is zero (or each offender is reviewed and
-- knowingly accepted).
--
-- Length semantics: char_length() counts CHARACTERS (Unicode code points),
-- matching the OpenAPI maxLength semantics the API now enforces (Huma
-- validates maxLength with utf8.RuneCountInString). Do NOT use octet_length.
--
-- Bounds under test:
--   agents (agent_identities).name ..................... 200
--   agents (agent_identities).id (the email) ........... 320
--   api_keys.name ...................................... 200
--   messages.conversation_id ........................... 200
--   messages.rejection_reason .......................... 2000
--   messages.to_recipients / cc / bcc (each element) ... 320
--
-- Read-only. Safe on prod (sequential scans on messages — run off-peak or
-- against a replica if the messages table is large).

\echo '=== agents.name > 200 chars ==='
SELECT count(*) AS violations, coalesce(max(char_length(name)), 0) AS max_len
  FROM agent_identities WHERE char_length(name) > 200;
SELECT id, char_length(name) AS len, left(name, 80) AS sample
  FROM agent_identities WHERE char_length(name) > 200
 ORDER BY char_length(name) DESC LIMIT 5;

\echo '=== agents.id (email) > 320 chars ==='
SELECT count(*) AS violations, coalesce(max(char_length(id)), 0) AS max_len
  FROM agent_identities WHERE char_length(id) > 320;
SELECT left(id, 100) AS sample, char_length(id) AS len
  FROM agent_identities WHERE char_length(id) > 320
 ORDER BY char_length(id) DESC LIMIT 5;

-- Informational (no bound shipped this PR — local-part charset/length
-- validation for custom domains is a stated follow-up): the classic RFC
-- local-part ceiling is 64.
\echo '=== INFO: agents.id local-part > 64 chars (follow-up, not gated) ==='
SELECT count(*) AS over_64, coalesce(max(char_length(split_part(id, '@', 1))), 0) AS max_len
  FROM agent_identities WHERE char_length(split_part(id, '@', 1)) > 64;

\echo '=== api_keys.name > 200 chars ==='
SELECT count(*) AS violations, coalesce(max(char_length(name)), 0) AS max_len
  FROM api_keys WHERE char_length(name) > 200;
SELECT id, char_length(name) AS len, left(name, 80) AS sample
  FROM api_keys WHERE char_length(name) > 200
 ORDER BY char_length(name) DESC LIMIT 5;

\echo '=== messages.conversation_id > 200 chars ==='
SELECT count(*) AS violations, coalesce(max(char_length(conversation_id)), 0) AS max_len
  FROM messages WHERE char_length(conversation_id) > 200;
SELECT id, char_length(conversation_id) AS len, left(conversation_id, 80) AS sample
  FROM messages WHERE char_length(conversation_id) > 200
 ORDER BY char_length(conversation_id) DESC LIMIT 5;

\echo '=== messages.rejection_reason > 2000 chars ==='
SELECT count(*) AS violations, coalesce(max(char_length(rejection_reason)), 0) AS max_len
  FROM messages WHERE char_length(rejection_reason) > 2000;
SELECT id, char_length(rejection_reason) AS len, left(rejection_reason, 80) AS sample
  FROM messages WHERE char_length(rejection_reason) > 2000
 ORDER BY char_length(rejection_reason) DESC LIMIT 5;

\echo '=== messages.to_recipients / cc / bcc: any element > 320 chars ==='
WITH rec AS (
    SELECT id, 'to'  AS kind, r AS addr FROM messages, unnest(to_recipients) AS r
    UNION ALL
    SELECT id, 'cc',  r FROM messages, unnest(cc)  AS r
    UNION ALL
    SELECT id, 'bcc', r FROM messages, unnest(bcc) AS r
)
SELECT count(*) AS violations, coalesce(max(char_length(addr)), 0) AS max_len
  FROM rec WHERE char_length(addr) > 320;
WITH rec AS (
    SELECT id, 'to'  AS kind, r AS addr FROM messages, unnest(to_recipients) AS r
    UNION ALL
    SELECT id, 'cc',  r FROM messages, unnest(cc)  AS r
    UNION ALL
    SELECT id, 'bcc', r FROM messages, unnest(bcc) AS r
)
SELECT id, kind, char_length(addr) AS len, left(addr, 80) AS sample
  FROM rec WHERE char_length(addr) > 320
 ORDER BY char_length(addr) DESC LIMIT 5;

-- send_attempts carries its own recipient copies (approve-path WAL) — scan it
-- too so a held draft replayed after deploy can't trip the new bound.
\echo '=== send_attempts.to_recipients / cc_recipients / bcc_recipients: any element > 320 chars ==='
WITH rec AS (
    SELECT message_id, 'to'  AS kind, r AS addr FROM send_attempts, unnest(to_recipients)  AS r
    UNION ALL
    SELECT message_id, 'cc',  r FROM send_attempts, unnest(cc_recipients)  AS r
    UNION ALL
    SELECT message_id, 'bcc', r FROM send_attempts, unnest(bcc_recipients) AS r
)
SELECT count(*) AS violations, coalesce(max(char_length(addr)), 0) AS max_len
  FROM rec WHERE char_length(addr) > 320;
