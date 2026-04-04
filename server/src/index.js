import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 8787);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error('Origin not allowed by proxy CORS policy.'));
  },
}));
app.use(express.json({ limit: '5mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'attack-nav-proxy' });
});

app.post('/api/opencti/graphql', async (req, res) => {
  const url = process.env.OPENCTI_URL;
  const token = process.env.OPENCTI_TOKEN;
  if (!url || !token) {
    res.status(500).json({ error: 'OpenCTI proxy is not configured.' });
    return;
  }

  try {
    const upstream = await fetch(`${url.replace(/\/$/, '')}/graphql`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: req.body?.query ?? '',
        variables: req.body?.variables ?? {},
      }),
    });

    const text = await upstream.text();
    res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : 'OpenCTI proxy request failed.' });
  }
});

const mispProxy = async (req, res) => {
  const url = process.env.MISP_URL;
  const apiKey = process.env.MISP_API_KEY;
  if (!url || !apiKey) {
    res.status(500).json({ error: 'MISP proxy is not configured.' });
    return;
  }

  const endpoint = req.params[0] || '';
  const targetUrl = `${url.replace(/\/$/, '')}/${endpoint}`;
  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers: {
        Authorization: apiKey,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: req.method === 'GET' ? undefined : JSON.stringify(req.body ?? {}),
    });

    const text = await upstream.text();
    res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json').send(text);
  } catch (error) {
    res.status(502).json({ error: error instanceof Error ? error.message : 'MISP proxy request failed.' });
  }
};

app.get('/api/misp/*', mispProxy);
app.post('/api/misp/*', mispProxy);

app.listen(port, () => {
  console.log(`attack-nav proxy listening on http://localhost:${port}`);
});
