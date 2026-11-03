# メsteem — Render Deployment Guide

## Included Files & Folder Structure

```text
steem-render/
├── public/
│   └── index.html        # Complete single-file メsteem frontend
├── server.js             # Express + WebSocket + Render PostgreSQL backend
├── package.json          # Node.js dependencies (express, pg, ws, dotenv)
├── render.yaml           # One-click Render Blueprint (Web Service + PostgreSQL)
└── .env.example          # Environment variable reference
```

## Deploying on Render.com

1. **Push this folder to a GitHub repository.**
2. **Option A — Automatic Blueprint (`render.yaml`)**:
   - In Render Dashboard, click **New +** -> **Blueprint** and select your repository.
   - Enter your chosen `ADMIN_EMAIL` and `ADMIN_PASSWORD` when prompted.
   - Render automatically creates the PostgreSQL database (`steem-postgres`), links `DATABASE_URL`, and deploys `server.js` + `public/index.html`.
3. **Option B — Manual Web Service + Render PostgreSQL**:
   - Create a **New PostgreSQL** instance on Render and copy its **Internal Database URL**.
   - Create a **New Web Service** connected to your repository:
     - **Build Command**: `npm install`
     - **Start Command**: `npm start`
   - Under **Environment Variables**, set:
     - `DATABASE_URL` = *(your Render PostgreSQL Internal URL)*
     - `ADMIN_EMAIL` = *(email for the Supreme Admin of メveil)*
     - `ADMIN_PASSWORD` = *(password for the Supreme Admin of メveil)*
     - `ADMIN_USERNAME` = `veil_sovereign` *(or your preferred handle)*

## Architecture Notes

- **PostgreSQL Persistence**: Stores only user credentials (`email`, `password_hash`, `username`) to remember returning users and resolve `@username` lookups, plus active 7-day group invite links (`group_invites`).
- **7-Day Group Links**: Mixed from your Render service URL (`RENDER_EXTERNAL_URL`) + a 24-character cryptographic token (`/?join=...`). Automatically deleted from PostgreSQL after 7 days; Group Admins can reset to generate a new 7-day link anytime in Group Settings.
- **Local Storage Vault**: Chat messages, cropped images, trimmed/cropped videos, voice notes, bios, and avatars are persisted on each user's device in `localStorage` and relayed live over WebSockets (`/ws`).
