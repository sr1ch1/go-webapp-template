import { FullConfig } from '@playwright/test';
import crypto from 'crypto';
import http from 'http';
import net from 'net';
import { spawn, spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const issuer = 'https://e2e.example.com';
const audience = 'e2e-audience';
const kid = 'e2e-key';

interface E2EState {
  baseURL: string;
  adminToken: string;
  viewerToken: string;
  appPID: number;
}

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as net.AddressInfo).port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

function generateKeyPair(): { privateKey: string; publicKey: string; jwk: crypto.JsonWebKey } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  return { privateKey, publicKey, jwk };
}

function signJWT(privateKey: string, claims: Record<string, unknown>): string {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(claims)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  const signature = signer.sign(privateKey, 'base64');
  const sigB64 = signature.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${signingInput}.${sigB64}`;
}

function startJWKSServer(port: number, jwk: crypto.JsonWebKey): http.Server {
  const server = http.createServer((req, res) => {
    if (req.url !== '/jwks.json') {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const body = JSON.stringify({
      keys: [
        {
          kty: 'RSA',
          kid,
          n: jwk.n,
          e: jwk.e,
          alg: 'RS256',
          use: 'sig',
        },
      ],
    });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(body);
  });
  server.listen(port, '127.0.0.1');
  return server;
}

async function waitForServer(baseURL: string, timeoutMs = 10000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${baseURL}/healthz`);
      if (res.status === 200) {
        return;
      }
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server at ${baseURL} did not become ready within ${timeoutMs}ms`);
}

function buildApp(): string {
  const binary = path.join(__dirname, 'webapp-e2e');
  const result = spawnSync('go', ['build', '-o', binary, '../cmd/app'], {
    cwd: __dirname,
    encoding: 'utf8',
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  if (result.status !== 0) {
    throw new Error(`failed to build app: ${result.stderr}`);
  }
  return binary;
}

async function startApp(binary: string, appPort: number, jwksURL: string): Promise<{ proc: ReturnType<typeof spawn>; pid: number }> {
  const proc = spawn(binary, [], {
    env: {
      ...process.env,
      APP_HTTP_ADDR: `127.0.0.1:${appPort}`,
      APP_DATABASE_PATH: ':memory:',
      APP_AUTH_PROVIDER: 'test',
      APP_AUTH_TEST_ISSUER: issuer,
      APP_AUTH_TEST_AUDIENCE: audience,
      APP_AUTH_TEST_JWKS_URL: jwksURL,
      APP_LOG_LEVEL: 'info',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proc.stdout?.on('data', (data) => process.stdout.write(`[app] ${data}`));
  proc.stderr?.on('data', (data) => process.stderr.write(`[app] ${data}`));

  if (!proc.pid) {
    throw new Error('failed to start app: no pid');
  }

  return { proc, pid: proc.pid };
}

export default async function globalSetup(_config: FullConfig): Promise<() => Promise<void>> {
  const appPort = await freePort();
  const jwksPort = await freePort();
  const baseURL = `http://127.0.0.1:${appPort}`;
  const jwksURL = `http://127.0.0.1:${jwksPort}/jwks.json`;

  const { privateKey, jwk } = generateKeyPair();
  const jwksServer = startJWKSServer(jwksPort, jwk);

  const now = Math.floor(Date.now() / 1000);
  const adminToken = signJWT(privateKey, {
    sub: 'e2e-admin',
    iss: issuer,
    aud: audience,
    exp: now + 3600,
    iat: now,
    email: 'admin@example.com',
    name: 'E2E Admin',
    roles: ['admin'],
  });
  const viewerToken = signJWT(privateKey, {
    sub: 'e2e-viewer',
    iss: issuer,
    aud: audience,
    exp: now + 3600,
    iat: now,
    email: 'viewer@example.com',
    name: 'E2E Viewer',
    roles: [],
  });

  const binary = buildApp();
  const { pid, proc } = await startApp(binary, appPort, jwksURL);

  try {
    await waitForServer(baseURL);
  } catch (err) {
    proc.kill('SIGTERM');
    throw err;
  }

  const statePath = path.join(__dirname, '.e2e-state.json');
  const state: E2EState = {
    baseURL,
    adminToken,
    viewerToken,
    appPID: pid,
  };
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2));

  process.env.E2E_BASE_URL = baseURL;
  process.env.E2E_ADMIN_TOKEN = adminToken;
  process.env.E2E_VIEWER_TOKEN = viewerToken;

  return async () => {
    proc.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      proc.on('exit', () => resolve());
      setTimeout(() => {
        proc.kill('SIGKILL');
        resolve();
      }, 5000);
    });
    jwksServer.close();
    for (const f of [binary, statePath]) {
      try {
        fs.unlinkSync(f);
      } catch {
        // ignore cleanup errors
      }
    }
  };
}
