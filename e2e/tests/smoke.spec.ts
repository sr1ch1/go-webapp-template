import { test, expect } from '@playwright/test';
import { envState } from '../fixtures/state';

const state = envState();

test.describe('unauthenticated routes', () => {
  test('healthz answers without auth', async ({ page }) => {
    const response = await page.request.get('/healthz');
    expect(response.status()).toBe(200);
    await expect(response.json()).resolves.toEqual({ status: 'ok' });
  });

  test('home requires authentication', async ({ page }) => {
    const response = await page.request.get('/', { headers: { 'Cf-Access-Jwt-Assertion': '' } });
    expect(response.status()).toBe(401);
  });
});

test.describe('admin user', () => {
  test.beforeEach(async ({ page }) => {
    await page.setExtraHTTPHeaders({
      'Cf-Access-Jwt-Assertion': state.adminToken,
    });
  });

  test('sees site name and principal dropdown', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('.site-name')).toContainText('Web App Template');
    await expect(page.locator('.principal-toggle')).toContainText('E2E Admin');
  });

  test('can edit runtime config via htmx', async ({ page }) => {
    await page.goto('/');
    const row = page.locator('tr:has-text("site_name")');
    const input = row.locator('input[name="value"]');
    await input.fill('E2E Site Name');
    await row.locator('button[type="submit"]').click();

    // htmx swaps the #config-section fragment without a full page reload.
    await expect(page.locator('tr:has-text("site_name") input[name="value"]')).toHaveValue('E2E Site Name');
  });

  test('principal dropdown shows details', async ({ page }) => {
    await page.goto('/');
    await page.locator('.principal-toggle').click();
    await expect(page.locator('.principal-details')).toContainText('e2e-admin');
    await expect(page.locator('.principal-details')).toContainText('admin@example.com');
    await expect(page.locator('.principal-details code')).toContainText('admin');
  });
});

test.describe('viewer user', () => {
  test.beforeEach(async ({ page }) => {
    await page.setExtraHTTPHeaders({
      'Cf-Access-Jwt-Assertion': state.viewerToken,
    });
  });

  test('sees config values but cannot edit', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('tr:has-text("site_name") td code')).toContainText('site_name');
    await expect(page.locator('input[name="value"]')).toHaveCount(0);
  });

  test('principal shows no admin role', async ({ page }) => {
    await page.goto('/');
    await page.locator('.principal-toggle').click();
    await expect(page.locator('.principal-details code')).toHaveCount(0);
  });
});

test.describe('security headers', () => {
  test('CSP is strict on authenticated pages', async ({ request }) => {
    const response = await request.get('/', {
      headers: { 'Cf-Access-Jwt-Assertion': state.viewerToken },
    });
    expect(response.status()).toBe(200);
    const csp = response.headers()['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
  });
});
