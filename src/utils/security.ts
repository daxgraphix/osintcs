/**
 * Security utilities for input sanitization, validation, and safe storage.
 */

export function escapeHtml(value: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  };
  return value.replace(/[&<>"']/g, (char) => map[char] || char);
}

export function sanitizeText(value: string, maxLength = 2000): string {
  const trimmed = value.trim().slice(0, maxLength);
  return escapeHtml(trimmed);
}

export function validateDomain(value: string): boolean {
  const cleaned = value.trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/.test(cleaned);
}

export function validateEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

export function validateHash(value: string): boolean {
  const cleaned = value.trim().toLowerCase();
  const hexRegex = /^[a-f0-9]+$/;
  if (!hexRegex.test(cleaned)) return false;
  return cleaned.length === 32 || cleaned.length === 40 || cleaned.length === 64;
}

export function validateIp(value: string): boolean {
  const cleaned = value.trim();
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv4Regex.test(cleaned) || ipv6Regex.test(cleaned);
}

export function validateUrl(value: string): boolean {
  const cleaned = value.trim();
  return /^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(cleaned);
}

export function validateUsername(value: string): boolean {
  const cleaned = value.trim();
  return cleaned.length >= 1 && cleaned.length <= 100 && /^[a-zA-Z0-9._-]+$/.test(cleaned);
}

export function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 200);
}

export function computeChecksum(data: string): string {
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

export function verifyStorageIntegrity(raw: string, expectedChecksum: string): boolean {
  const [data, checksum] = raw.split('|');
  if (!data || !checksum) return false;
  return computeChecksum(data) === checksum;
}

export function packStorage(data: string): string {
  const checksum = computeChecksum(data);
  return `${data}|${checksum}`;
}

export function unpackStorage(packed: string): string | null {
  const [data, checksum] = packed.split('|');
  if (!data || !checksum) return null;
  if (computeChecksum(data) !== checksum) return null;
  return data;
}
