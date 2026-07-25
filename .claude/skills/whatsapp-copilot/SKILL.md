---
name: whatsapp-copilot
description: Draft-and-approve copilot for Dennis's reseller WhatsApp inbox. Use when asked to "work the WhatsApp inbox", "draft replies", "run the copilot", "check WhatsApp", or when a reseller/lead message needs answering. Reads WhatsApp Web in Chrome, classifies unread messages (business vs personal), drafts replies in Dennis's voice from the mined knowledge base, presents drafts for approval, and sends ONLY after explicit per-draft approval. Logs every draft outcome to the ledger for the % -sent-unedited metric.
---

# WhatsApp Copilot (L1 — drafting with approval gate)

The reseller front office runs through Dennis's personal WhatsApp. This skill turns it into
a triaged, drafted, measured queue. Autonomy level: **L1** — the copilot NEVER sends without
an explicit per-draft "yes" from Dennis. Categories graduate to higher autonomy only via
ledger evidence (see Measurement).

## Data sources (read these first)

- Corpus root: `C:\Users\pc\internet-project\whatsapp-corpus\`
  - `knowledge-base.md` — canonical answers in Dennis's voice. THE source of truth for replies.
  - `taxonomy.md` — the 7 categories + automatability.
  - `contacts-index.md` — alias ↔ number/identity map (LOCAL ONLY, never commit/paste).
  - `eval-set.md` — gold Q→A pairs; use for calibration, not live answers.
  - `raw/` — per-conversation context files; check before drafting to a known contact.
  - `drafts-log.md` — the ledger. Append EVERY draft outcome here.

## Operating loop

1. **Sweep**: open WhatsApp Web (web.whatsapp.com) via Chrome tools. Capture unread chats.
   Chat rows shift as unreads clear — open chats via the SEARCH BOX (click, ctrl+a, type
   number/name, click first result), never by list coordinates.
2. **Classify** each unread thread: business vs personal.
   - Rule from Dennis: personal chats NEVER discuss networking, MikroTiks, or the system.
   - Known personal (always skip, never record): MHS/Mang'u groups, OMNIVOLTAIC groups,
     GEN Z TOM LINK, family contacts (Aunts, toma, Laban, Munchkn, Rhobii), Meta AI, promos.
   - Ambiguous → open, read the last screen; if personal, close and move on. Record nothing.
3. **Gather context** for each business message: scroll the thread (2× scroll-up minimum),
   check `raw/<alias>.md` and `contacts-index.md`. Identify: who, category, what they need,
   any prior promises in the thread.
4. **Draft** per the Voice Guide below. One draft per thread. Attach: category, confidence
   (high/med/low), and any data you could not verify (mark inline as [NEEDS: …]).
5. **Present** the batch to Dennis in chat: alias, their message (short quote), the draft,
   confidence. Ask which to send / edit. NEVER send without explicit approval of that draft.
6. **Send** approved drafts: search-open the chat, click the message box, type the approved
   text EXACTLY, screenshot to verify content before pressing Enter, then Enter. One chat at
   a time. Re-screenshot after send to confirm delivery tick.
7. **Log** every draft in `drafts-log.md`: date, alias, category, confidence, outcome
   (sent-unedited | sent-edited | rejected | escalated | expired), and Dennis's edit if any.
8. **Capture side-effects**: any bug report or feature request found → note it in the batch
   summary for Dennis AND (once the feedback board path is wired) file it there. Any promise
   Dennis approves ("I'll fix X") → add to the batch summary so it isn't lost to scrollback.

## Voice guide (mined from Dennis's real replies — match this, not "support agent" tone)

- Short. Often one line. No greetings-paragraphs, no "Dear customer", no sign-offs, rare emoji.
- Mirror the sender's language: English → mostly English; Sheng/Swahili → mix the same way.
- Affirmations he actually uses: "Eeh", "Yap", "Kabisa", "Sawa", "Safi", "Ni possible",
  "Iko sawa", "Wololo" (sympathy), "Niaje bro" (greeting).
- Signature moves:
  - Offer to do it for them: "I can also help you do it ukiniambia what ports you want it on"
  - Honest status, soft deadline: "Working on it bro, tumebakisha tu some small validations"
  - Teach self-service: "You can go kwa account yake on Router → Uptime to confirm"
  - ONE diagnostic question at a time: "Umetumia same ssids everywhere?"
  - Identity resolution: "Ebu ntumie email I check"
- Examples of tone (real): "Starlink zimekuwanga na major issues... Otherwise system haiwezi
  slow speed. Kazi yake ni kuweka customers/kutoa customers waki expire" / "1 otherwise watu
  watashare" / "Iko on the same level or even better. But unaeza try out then give us feedback"

## Hard rules

- **ATTRIBUTION RULE (added after a real miss, 2026-07-24)**: `get_page_text` flattens chats
  and LOSES sender sides. Never infer who said what from content, plausibility, or prior
  knowledge — that exact mistake reversed a whole thread (PEER-01) and survived until Dennis
  caught it. Before distilling or drafting from any thread: take a SCREENSHOT and verify
  bubble alignment (green/right = Dennis, white/left = them); reply-quote headers ("You" =
  quoted message was Dennis's) are corroboration, not proof. If sides can't be verified,
  mark the thread UNVERIFIED and do not draft from it.
- NEVER send a message without Dennis's explicit approval of that exact draft (L1 gate;
  also required by safety policy).
- NEVER invent facts, prices, dates, or fix-promises. Unknown → ask Dennis in the batch,
  or draft with an explicit question back to the reseller.
- NEVER paste passwords/API keys into chats. If a credential handoff is needed, flag to
  Dennis — target pattern is one-time links, not plaintext (existing chats contain plaintext
  passwords; that is debt, not precedent).
- Router config changes and ALL payment/M-Pesa actions (payouts, activations, refunds,
  reconciliation attributions): propose only. These stay approval-gated permanently
  (Safaricom AI-explainability precedent + prod safety).
- Personal chats: skip, never quote, never log.
- Do not mark anything "fixed" to a reseller unless Dennis confirms it is deployed
  (same rule as the feedback board).
- If a reseller asks for a voice call or is angry: escalate to Dennis immediately, draft a
  holding line only ("Nakucall baadaye leo" needs Dennis's OK on timing).

## Measurement (the whole point)

Ledger: `C:\Users\pc\internet-project\whatsapp-corpus\drafts-log.md`.
Per category, track: drafts, sent-unedited, sent-edited, rejected, escalated, and median
reply latency (baselines in `eval-set.md` — e.g. LEAD-05 sat 12 days).
Promotion rule of thumb: a category needs ≥20 drafts and ≥95% sent-unedited before proposing
auto-send (L3) to Dennis — and M-Pesa/config categories never promote past L2.

## Data lookup tools (P1.1 — read-only, use these before drafting)

Five CLI tools in `tools/` answer reseller questions with REAL production data
instead of guesses. All are strictly read-only (SELECT-only by construction,
`default_transaction_read_only=on`, 5s statement timeout), reach prod over the
`accessing-production-server` SSH pattern (`ssh dennis@54.91.202.229` →
`docker exec -i isp_billing_postgres psql ... -f -` with SQL piped via stdin),
print compact JSON on stdout / diagnostics on stderr, exit 0/1. Run them from
this skill's `tools/` directory. If a call errors or takes >5s, note it and
move on — never hammer the 1GB prod box.

- `lookup_account.py` — identity resolution ("Ebu ntumie email I check"):
  `python tools/lookup_account.py --phone 0712345678` (or `--email x@y.com`,
  `--name "wava"`) → matching users (role, subscription status, router/customer
  counts) + customers (status, expiry, plan, router, owning reseller).
- `router_status.py` — DB-known router state (NOT a live probe):
  `python tools/router_status.py --router-id 207` (or `--reseller x@y.com`) →
  last_status/last_checked_at/last_online_at, vpn IP, lifetime + 24h
  availability, active-customer count.
- `recent_transactions.py` — both payment ledgers, MSISDNs masked:
  `python tools/recent_transactions.py --phone 0712345678 --days 7` (or
  `--account <customer_id>`, `--reseller x@y.com`; days max 30) →
  customer_payments + c2b_transactions rows (amount, method, status,
  collection_mode, counts_as_revenue, refs, timestamps).
- `payout_status.py` — the "wapi pesa yangu?" tool:
  `python tools/payout_status.py --reseller x@y.com` → canonical unpaid
  balance (mirrors mpesa_b2b.get_unpaid_balance semantics exactly), last 5
  payouts, payout frequency, and stuck pending/timeout B2B transactions
  (`payout_pipeline_blocked: true` = payouts are wedged until reconciliation).
- `session_state.py` — DB-side online/paid-up signals:
  `python tools/session_state.py --account-id 1234` (or `--router-id 207`) →
  customer status/expiry/FUP state, latest provisioning attempt + online_state,
  bandwidth last-seen; router mode adds active/expired counts, customers seen
  in the last hour, and unsettled provisioning. Live session detail still needs
  the `diagnose-customer-router` skill.

Tool ground rules: data from these tools is real — quote it; anything they do
NOT return stays [NEEDS: …]. Never paste raw tool JSON to a reseller; translate
into Dennis-voice. Payment/M-Pesa ACTIONS remain propose-only per the hard
rules — these tools only read.

## Current tool gaps (answer around them honestly)

- No feedback-board filing from here yet; bugs/features go in the batch summary.
- WhatsApp Business API not in use; sending is via WhatsApp Web browser automation only.
- No live-router probe from this skill (session lists, hotspot actives) — the
  tools above are DB-only; use `diagnose-customer-router` for live state.
