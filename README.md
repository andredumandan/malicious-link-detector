# Malicious Link Detector

A webapp that analyzes URLs for security threats using local heuristics + external threat-intel APIs.

## Stack
- **Frontend:** React + Vite + TypeScript + Tailwind CSS (deployed on Vercel)
- **Backend:** Node.js + Express + TypeScript (deployed on Render)

## Quick Start

### Prerequisites
- Node.js 22+
- API keys (optional — app works with heuristics-only offline):
  - [Google Safe Browsing API](https://developers.google.com/safe-browsing/v4/get-started)
  - [VirusTotal API](https://www.virustotal.com/gui/join-us)

### Development

```bash
# Backend
cd backend
cp .env.example .env
# Edit .env and add your API keys
npm install
npm run dev

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:5173`, backend on `http://localhost:3001`.

### Testing

```bash
cd frontend && npm test
cd backend && npm test
```

## Deployment

### Frontend → Vercel
1. Push the repo to GitHub
2. Import the `frontend` directory as a new Vercel project
3. Vercel auto-detects Vite — no extra config needed
4. Set env var `VITE_API_URL` to your Render backend URL (optional, defaults to same origin)

### Backend → Render
1. Create a new Web Service on Render, point it to the `backend` subdirectory
2. Build command: `npm install && npm run build`
3. Start command: `npm start`
4. Add env vars:
   - `PORT`: `3001`
   - `SAFE_BROWSING_API_KEY`: your key
   - `VIRUSTOTAL_API_KEY`: your key

Or use the included `render.yaml` for Infrastructure-as-Code.

## How It Works

1. **Local Heuristics** (instant, works offline): Checks the URL for IP-based domains, excessive subdomains, URL shorteners, suspicious keywords, typosquatting, long URLs, missing HTTPS, high-entropy patterns
2. **Google Safe Browsing**: Checks against Google's malware/phishing blocklist
3. **VirusTotal**: Submits the URL and aggregates vendor flags
4. **Redirect Following**: Resolves shortened URLs to reveal the final destination
