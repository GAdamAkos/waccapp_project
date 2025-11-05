# WhatsApp Webhook App — Surveys, Templates & Scheduling (Node.js + Express + SQLite)

A production‑ready demo app for **WhatsApp Business API** workflows:
- **Template (button) flows** and **free‑text questionnaires**
- **Automatic chaining** to the next question based on the user’s reply
- **Media sending** (images/docs) and **file uploads**
- **Scheduled** messages/templates/questionnaires
- **Webhook** receiver with verification
- **SQLite** storage for messages, users, sessions, and questionnaire data

> Default timezone: **Europe/Budapest** (change via `APP_TZ`/`TZ`).

---

## 📦 Project layout (relevant bits)

```
wacapp/szakmai_gyak_projekt/vegleges/proba/webhook-main/
  app.js                   # Express server: webhook, sending, scheduler, DB init, static UI
  package.json
  public/                  # Frontend UI (forms, chat view, assets, uploaded media under sent_media/)
  kerdoivek/               # Text-based questionnaires (JSON/JS), served as static
  questionnaire.js         # Template-based questionnaire flows
  whatsapp_messages.db     # SQLite DB (created on first run)
```

There are other folders in the archive (old `.git/`, `.idea/`, etc.) that **should not** go to GitHub.

---

## 🚀 Quick start

### Prerequisites
- **Node.js 18+**
- A **WhatsApp Business** setup in Meta (WABA ID, token, webhook URL)

### Setup & run
```bash
cd wacapp/szakmai_gyak_projekt/vegleges/proba/webhook-main
npm install

cp ../../../.env.example .env   # create your .env next to app.js
# then edit .env minimally:
# PORT=3000
# VERIFY_TOKEN=your_webhook_verify_token
# WHATSAPP_BUSINESS_ACCOUNT_ID=your_waba_id
# ACCESS_TOKEN=your_long_lived_access_token
# (optional) APP_TZ=Europe/Budapest
# (optional) ALLOWED_EMAIL_DOMAINS=example.com,example.org
# (optional) ALLOW_SELF_SIGNUP=true

npm start         # starts Express on PORT (default: 3000)
```

Open the UI (if provided) at: `http://localhost:3000/`

---

## 🔌 Webhook verification

Meta calls your webhook with `GET /webhook` during setup.

Required env:
- `VERIFY_TOKEN` — must **match** the value you enter on the Meta Developer page.

If valid, the app echoes the `hub.challenge` and verification succeeds.

Incoming WhatsApp events are POSTed to `/webhook` (handled inside `app.js`).

---

## 🔐 Environment variables (essentials)

- `PORT` — HTTP port (default **3000**)
- `VERIFY_TOKEN` — webhook verification token (must match in Meta setup)
- `WHATSAPP_BUSINESS_ACCOUNT_ID` — your WABA ID
- `ACCESS_TOKEN` — Graph API access token (long‑lived recommeded)
- `APP_TZ`/`TZ` — timezone (default **Europe/Budapest**)
- `ALLOWED_EMAIL_DOMAINS` — comma‑separated list to allow signups (optional)
- `ALLOW_SELF_SIGNUP` — `true/false` (optional)

> The provided `.env.example` contains many system variables — you **only** need the ones above to start.

---

## 🗄️ Data & storage

- **Main DB**: `whatsapp_messages.db` created in the app directory.
- **Sessions**: `data/sessions.sqlite` (created on demand).
- **Questionnaires**: served from `./kerdoivek/` and `./questionnaire.js`.
- **Static**: UI and media served from `public/`:
  - `/sent-media` → `public/sent_media/`
  - `/uploads`    → `public/uploads/`
  - `/kerdoivek`  → `kerdoivek/`


---

## ✉️ Sending & flows

- Template list: `GET /available-templates` (requires `WHATSAPP_BUSINESS_ACCOUNT_ID`, `ACCESS_TOKEN`).
- First template per questionnaire: `GET /first-templates`.
- Free‑text & template questionnaires: defined in `questionnaire.js` and under `kerdoivek/`.
- File/media sending supported via UI endpoints (see `public/` forms) and handlers in `app.js`.

---

## 🛡️ Hardening

- Uses `helmet`, rate‑limiting, and session store (`connect-sqlite3`).
- Password utilities are present (`bcryptjs`). Configure self‑signup with `ALLOW_SELF_SIGNUP` if needed.
- Always keep your `.env` **out of Git**.

---

## 🧪 Dev tips

- Clear sessions with the provided helper in code (see `killUserSessions`).
- Restart on changes with `nodemon` (optional): `npx nodemon app.js`.

---
