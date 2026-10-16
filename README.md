# WatcherOsint backend — v1.0

Three Flask blueprints (`Number.py`, `Email.py`, `Username.py`) registered
by `app.py`. Each is deliberately scoped to **existence/classification
checks**, not profile-building: no contact-import, no age/profession
inference, no cross-platform face matching, no auto-generated link-analysis
graph, and no identifier harvesting from scanned pages.

## Run it

```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
export ALLOWED_ORIGINS="http://127.0.0.1:5500"     # the origin your frontend is served from
python app.py
```

The API now listens on `http://127.0.0.1:5000`. Open `settings.html` in the
frontend and set **API connection → Backend base URL** to that address.

## Endpoints

- `GET /api/health`
- `GET /api/phone?number=+98911...`
- `GET /api/email?email=you@example.com&iranian=1`
- `GET /api/username?u=handle&region=all|iran|global&proxy=...`

## Deploying for real (GitHub can't run Python by itself)

GitHub Pages only serves static files — it cannot run `app.py`. So this is
**two separate deployments**:

**1. Frontend (the 6 .html files) → GitHub Pages**
1. Push `index.html`, `login.html`, `phone.html`, `email.html`, `username.html`,
   `settings.html` to the repo (root of the `main` branch is simplest).
2. Repo → Settings → Pages → Source: `main` branch, `/ (root)`.
3. Your site goes live at `https://watcheram.github.io/WatcherAm/`.

**2. Backend (this `backend/` folder) → Render, Railway, Fly.io, or a VPS**
(pick one; Render's free tier is the simplest to start with)
1. New → Web Service → connect the same GitHub repo.
2. Root directory: `backend`. Build command: `pip install -r requirements.txt`.
   Start command: `gunicorn app:app`.
3. Environment variables: `ALLOWED_ORIGINS=https://watcheram.github.io`
   (exactly your Pages origin, no trailing slash), plus `NUMVERIFY_API_KEY` /
   `HUNTER_API_KEY` if you have them.
4. Deploy → you get a URL like `https://watcherosint-api.onrender.com`.

**3. Connect them**
Open your live site → `settings.html` → **API connection** → paste the
Render URL into **Backend base URL** → Save. The health pill in the header
will turn green once it can reach it.

**Important: both sides must be HTTPS.** GitHub Pages is always `https://`.
If the backend is still `http://`, browsers silently block the frontend
from calling it (mixed content). Render/Railway/Fly give you `https://`
automatically — just don't point Settings at an `http://` URL in production.

## Before you deploy this publicly

- Set `ALLOWED_ORIGINS` to your real frontend domain, not `*`.
- Put `NUMVERIFY_API_KEY` / `HUNTER_API_KEY` in the server's environment,
  never in a browser-side field.
- Put a real rate limiter (Redis-backed) in front of this — the in-memory
  limiter in each module is per-process and resets on restart.
- `Email.py`'s `ADAPTERS` dict ships empty on purpose. Add a verified
  adapter per site only once you've confirmed its actual "already
  registered" signal — don't guess at indicator strings, since a wrong
  guess reports false positives about real people.
