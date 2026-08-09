import fs from 'fs';
import path from 'path';

export interface E2EState {
  baseURL: string;
  adminToken: string;
  viewerToken: string;
}

export function loadState(): E2EState {
  const statePath = path.join(__dirname, '..', '.e2e-state.json');
  const raw = fs.readFileSync(statePath, 'utf8');
  return JSON.parse(raw) as E2EState;
}

export function envState(): E2EState {
  return {
    baseURL: process.env.E2E_BASE_URL!,
    adminToken: process.env.E2E_ADMIN_TOKEN!,
    viewerToken: process.env.E2E_VIEWER_TOKEN!,
  };
}
