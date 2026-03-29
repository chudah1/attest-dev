# Attest Dashboard App

This is the standalone React/Vite dashboard for Attest. The public site can stay static HTML while the authenticated product surface deploys independently.

## Local development

Install dependencies and start the Vite dev server:

```bash
cd dashboard-app
npm install
npm run dev
```

By default the app talks to `https://api.attestdev.com`.

To point the dashboard at a different backend:

```bash
VITE_API_BASE_URL=http://localhost:8080 npm run dev
```

## Production build

```bash
cd dashboard-app
npm run build
npm run preview
```

The production assets are written to `dashboard-app/dist`.

## Deploy to Vercel

1. Import this repo into Vercel.
2. Set the root directory to `dashboard-app`.
3. Let Vercel use the Vite preset.
4. Set `VITE_API_BASE_URL=https://api.attestdev.com`.
5. Deploy.

Recommended follow-up configuration:

- Add a custom domain such as `app.attestdev.com`.
- Set the backend env var `CORS_ORIGINS=https://www.attestdev.com,https://app.attestdev.com`.
- Set the backend env var `DASHBOARD_URL=https://app.attestdev.com` so `https://api.attestdev.com/dashboard` redirects to the standalone app.

## Notes

- The app keeps the existing Attest UI language: indigo surfaces, serif display treatment, and the same audit/evidence flows.
- The browser smoke tests load the built app from `dashboard-app/dist`, so run `npm run build` before the dashboard smoke suite if you change frontend code.
