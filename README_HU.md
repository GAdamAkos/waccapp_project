# WhatsApp Webhook App — Kérdőív, sablonok és időzítés (Node.js + Express + SQLite)

Egy **WhatsApp Business API** demó/portfólió app, ami éles logikával dolgozik:
- **Gombos sablonok** és **szöveges kérdőívek**
- **Automatikus továbbléptetés** a válasz alapján (sablonlánc)
- **Média küldés** (kép/dokumentum) és fájlfeltöltés
- **Időzített** üzenetek/sablonok/kérdőívek
- **Webhook** fogadás és verifikáció
- **SQLite** tárolás (üzenetek, userek, sessionök, kérdőívadatok)

> Alap időzóna: **Europe/Budapest** (állítható `APP_TZ` / `TZ`).

---

## 📦 Mappaszerkezet (lényeg)

```
wacapp/szakmai_gyak_projekt/vegleges/proba/webhook-main/
  app.js                   # Express szerver: webhook, küldés, időzítő, DB init, statikus UI
  package.json
  public/                  # Frontend UI (űrlapok, chat nézet, assetek, feltöltött képek a sent_media/ alatt)
  kerdoivek/               # Szöveges kérdőívek (JSON/JS), statikusan kiszolgálva
  questionnaire.js         # Sablonos kérdőív-láncok leírása
  whatsapp_messages.db     # SQLite DB (első indításkor jön létre)
```

A zipben van még pár fejlesztői mappa (régi `.git/`, `.idea/`, stb.) — ezeket **ne** töltsd fel.

---

## 🚀 Gyors indítás

### Előfeltételek
- **Node.js 18+**
- **WhatsApp Business** Meta oldalon (WABA ID, token, webhook URL)

### Telepítés és futtatás
```bash
cd wacapp/szakmai_gyak_projekt/vegleges/proba/webhook-main
npm install

cp ../../../.env.example .env   # .env az app.js mellé
# szerkeszd ki a minimális értékeket:
# PORT=3000
# VERIFY_TOKEN=valami_amit_a_Meta_oldalon_is_megadsz
# WHATSAPP_BUSINESS_ACCOUNT_ID=a_te_waba_idd
# ACCESS_TOKEN=hosszu_elettu_graph_api_token
# (opció) APP_TZ=Europe/Budapest
# (opció) ALLOWED_EMAIL_DOMAINS=example.com,example.org
# (opció) ALLOW_SELF_SIGNUP=true

npm start         # Express indul a PORT-on (alap: 3000)
```

UI (ha van): `http://localhost:3000/`

---

## 🔌 Webhook verifikáció

A Meta a webhook beállításakor `GET /webhook`-ot hív.

Szükséges változó:
- `VERIFY_TOKEN` — **pont** egyezzen azzal, amit a Meta Developer felületen megadsz.

Ha stimmel, az app visszaadja a `hub.challenge`-et, és a verifikáció sikeres.

Bejövő WhatsApp eventek: `POST /webhook` (kezeli az `app.js`).

---

## 🔐 Környezeti változók (lényeg)

- `PORT` — HTTP port (**3000** az alap)
- `VERIFY_TOKEN` — webhook verifikációs token
- `WHATSAPP_BUSINESS_ACCOUNT_ID` — WABA ID
- `ACCESS_TOKEN` — Graph API token (lehetőleg hosszú élettartamú)
- `APP_TZ` / `TZ` — időzóna (alap: **Europe/Budapest**)
- `ALLOWED_EMAIL_DOMAINS` — engedélyezett e‑mail domainek (opció)
- `ALLOW_SELF_SIGNUP` — `true/false` (opció)

> A csomagolt `.env.example` sok rendszer‑változót is listáz — induláshoz **elég** a fenti pár.

---

## 🗄️ Adat és tárhely

- **Fő DB**: `whatsapp_messages.db` az app mappájában.
- **Session DB**: `data/sessions.sqlite` (ha szükséges, létrejön).
- **Kérdőívek**: `./kerdoivek/` és `./questionnaire.js`.
- **Statikus**: `public/`-ból szolgál ki:
  - `/sent-media` → `public/sent_media/`
  - `/uploads`    → `public/uploads/`
  - `/kerdoivek`  → `kerdoivek/`

> Tipp: élesben ne commitold a `*.db` fájlokat.

---

## ✉️ Küldés és folyamatok

- Sablonlista: `GET /available-templates` (kell: `WHATSAPP_BUSINESS_ACCOUNT_ID`, `ACCESS_TOKEN`).
- Első sablon kérdőívenként: `GET /first-templates`.
- Szöveges/sablonos kérdőívek: `questionnaire.js` és a `kerdoivek/` mappa.
- Fájl/média küldés: UI űrlapokból (lásd `public/`) és `app.js` végpontokon.

---

## 🛡️ Biztonság

- `helmet`, rate‑limit, `connect-sqlite3` session store
- `bcryptjs` jelszó utilities — `ALLOW_SELF_SIGNUP`-pal állítható önregisztráció
- `.env` **sose** kerüljön Gitbe

---

## 🧪 Fejlesztői tippek

- Session tisztítás: `killUserSessions` a kódban.
- Automatikus újraindítás: `npx nodemon app.js` (opcionális).

---
