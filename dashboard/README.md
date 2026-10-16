# SecretSweep AI — Dashboard

React + Vite + TailwindCSS frontend for SecretSweep AI. Provides the repository, developer,
timeline, and severity views described in the root [`README.md`](../README.md) and
[`CLAUDE.md`](../CLAUDE.md).

## Development

```bash
cp .env.example .env   # set VITE_API_BASE_URL if the API isn't on localhost:8000
npm install
npm run dev             # http://localhost:3000
```

## Build

```bash
npm run build
npm run preview
```

## Structure

```
src/
├── api/client.js        # axios instance pointed at the FastAPI backend
├── components/Layout.jsx # shared nav shell
├── pages/                # RepositoryView, DeveloperView, TimelineView, SeverityView
├── App.jsx                # route definitions
└── main.jsx                # React entrypoint
```
