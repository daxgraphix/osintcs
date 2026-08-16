/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * OSINT.CS API Proxy Server
 *
 * This server proxies requests to public APIs that block browser CORS.
 * Run with: npm run dev:proxy
 *
 * Supported endpoints:
 * - /api/ipify -> https://api.ipify.org?format=json
 * - /api/ipapi -> https://ipapi.co/json/
 * - /api/otx -> https://otx.alienvault.com/api/v1/indicators/file/:hash/:endpoint
 * - /api/keybase -> https://keybase.io/_/api/1.0/user/lookup.json?username=:username
 * - /api/disify -> https://www.disify.com/api/email/:email
 */

import express from 'express';
import cors from 'cors';
import { createProxyMiddleware } from 'http-proxy-middleware';

const app = express();
const PORT = process.env.PROXY_PORT || 3001;

app.use(cors());
app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use('/api/ipify', createProxyMiddleware({
  target: 'https://api.ipify.org',
  changeOrigin: true,
  pathRewrite: { '^/api/ipify': '/' },
  onError: (err, _req, res) => {
    console.error('ipify proxy error:', err);
    res.status(500).json({ error: 'IPify proxy failed' });
  },
}));

app.use('/api/ipapi', createProxyMiddleware({
  target: 'https://ipapi.co',
  changeOrigin: true,
  pathRewrite: { '^/api/ipapi': '/' },
  onError: (err, _req, res) => {
    console.error('ipapi proxy error:', err);
    res.status(500).json({ error: 'IPAPI proxy failed' });
  },
}));

app.use('/api/otx', createProxyMiddleware({
  target: 'https://otx.alienvault.com',
  changeOrigin: true,
  pathRewrite: { '^/api/otx': '/' },
  onError: (err, _req, res) => {
    console.error('OTX proxy error:', err);
    res.status(500).json({ error: 'OTX proxy failed' });
  },
}));

app.use('/api/keybase', createProxyMiddleware({
  target: 'https://keybase.io',
  changeOrigin: true,
  pathRewrite: { '^/api/keybase': '/' },
  onError: (err, _req, res) => {
    console.error('Keybase proxy error:', err);
    res.status(500).json({ error: 'Keybase proxy failed' });
  },
}));

app.use('/api/disify', createProxyMiddleware({
  target: 'https://www.disify.com',
  changeOrigin: true,
  pathRewrite: { '^/api/disify': '/' },
  onError: (err, _req, res) => {
    console.error('Disify proxy error:', err);
    res.status(500).json({ error: 'Disify proxy failed' });
  },
}));

app.listen(PORT, () => {
  console.log(`OSINT.CS API Proxy running on http://localhost:${PORT}`);
});
