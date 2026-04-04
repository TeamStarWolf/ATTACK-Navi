# ATT&CK NAV Proxy

Optional backend proxy for secure OpenCTI and MISP deployments.

## Why it exists

The Angular app can still run in direct browser mode, but direct mode means the browser holds integration secrets in memory. This proxy lets you:

- keep OpenCTI and MISP secrets in server-side environment variables
- restrict browser access with CORS
- expose only the minimal endpoints the frontend needs

## Quick start

1. Install dependencies:

```bash
npm install
```

2. Create an environment file:

```bash
copy .env.example .env
```

3. Fill in:

- `OPENCTI_URL`
- `OPENCTI_TOKEN`
- `MISP_URL`
- `MISP_API_KEY`
- `ALLOWED_ORIGINS`

4. Start the proxy:

```bash
npm start
```

Default URL: `http://localhost:8787`

## Frontend setup

In the ATT&CK NAV Settings panel:

- choose `Secure backend proxy` for OpenCTI and/or MISP
- enter the proxy base URL, such as `http://localhost:8787`

The browser will then call:

- `POST /api/opencti/graphql`
- `GET|POST /api/misp/*`

without storing the real upstream secrets client-side.
