/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/// <reference types="vite/client" />

const PROXY_URL = import.meta.env.VITE_API_PROXY_URL || '';

export function isProxyEnabled(): boolean {
  return Boolean(PROXY_URL);
}

export function proxyUrl(path: string): string {
  if (!PROXY_URL) return path;
  return `${PROXY_URL}${path}`;
}

export async function proxyFetch(url: string, options?: RequestInit): Promise<Response> {
  if (!PROXY_URL) {
    return fetch(url, options);
  }
  const proxied = new URL(url);
  const target = new URL(PROXY_URL);
  target.pathname = proxied.pathname;
  target.search = proxied.search;
  return fetch(target.toString(), options);
}
