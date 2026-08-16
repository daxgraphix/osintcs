/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { TimelineEvent } from '../types';

export function buildTimeline(scanResults: {
  whois?: any;
  ssl?: any;
}): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  const { whois, ssl } = scanResults;

  if (whois) {
    if (whois.creationDate) {
      events.push({
        id: 'TL_WHOIS_CREATION',
        date: whois.creationDate,
        title: 'Initial Domain Registration',
        description: `Domain was first registered through "${whois.registrar || 'Registrar'}"`,
        category: 'whois',
      });
    }
    if (whois.updatedDate) {
      events.push({
        id: 'TL_WHOIS_UPDATED',
        date: whois.updatedDate,
        title: 'Last Registration Update',
        description: 'Domain details or nameservers were modified or renewed.',
        category: 'whois',
      });
    }
    if (whois.expiryDate) {
      events.push({
        id: 'TL_WHOIS_EXPIRY',
        date: whois.expiryDate,
        title: 'Domain Registration Expiration',
        description: 'The current domain registration lease is scheduled to expire.',
        category: 'whois',
      });
    }
  }

  if (ssl) {
    if (ssl.validFrom) {
      events.push({
        id: 'TL_SSL_START',
        date: ssl.validFrom,
        title: 'SSL Certificate Issued',
        description: `A cryptographic SSL certificate was issued by "${ssl.issuer || 'CA'}"`,
        category: 'ssl',
      });
    }
    if (ssl.validTo) {
      events.push({
        id: 'TL_SSL_EXPIRY',
        date: ssl.validTo,
        title: 'SSL Certificate Expiration',
        description: 'The current certificate expires and must be replaced to prevent browser trust errors.',
        category: 'ssl',
      });
    }
  }

  return events.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
}
