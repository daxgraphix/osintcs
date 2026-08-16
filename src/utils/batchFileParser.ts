/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { InvestigationTarget } from '../types';

const MAX_BATCH_FILE_SIZE = 5 * 1024 * 1024;
const MAX_BATCH_CONTENT_LENGTH = 200000;
const MAX_BATCH_TARGETS = 200;

export interface BatchFileOptions {
  onSuccess: (targets: string[]) => void | Promise<void>;
  onError: (message: string) => void;
  maxTargets?: number;
}

export function validateBatchFile(file: File): string | null {
  if (file.size > MAX_BATCH_FILE_SIZE) {
    return 'Batch file too large. Maximum size is 5MB.';
  }
  const isTextOrCsv = file.name.endsWith('.txt') || file.name.endsWith('.csv') ||
    file.type === 'text/plain' || file.type === 'text/csv';
  if (!isTextOrCsv) {
    return 'Invalid file type. Please upload .txt or .csv files.';
  }
  return null;
}

export function parseBatchContent(content: string): string[] {
  if (!content || content.length > MAX_BATCH_CONTENT_LENGTH) {
    throw new Error('File content exceeds maximum allowed size.');
  }
  const targets = content
    .split(/[\n,;]+/)
    .map(t => t.trim())
    .filter(Boolean);
  if (targets.length === 0) {
    throw new Error('No valid targets found in batch file.');
  }
  if (targets.length > MAX_BATCH_TARGETS) {
    throw new Error('Batch limit exceeded. Maximum 200 targets per batch.');
  }
  return targets;
}

export async function processBatchFile(file: File, options: BatchFileOptions): Promise<void> {
  const validationError = validateBatchFile(file);
  if (validationError) {
    options.onError(validationError);
    return;
  }

  try {
    const content = await readFileAsText(file);
    const targets = parseBatchContent(content);
    await options.onSuccess(targets);
  } catch (err) {
    console.error('Failed to parse batch file:', err);
    options.onError(err instanceof Error ? err.message : 'Failed to read batch file.');
  }
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      resolve(event.target?.result as string);
    };
    reader.onerror = () => {
      reject(new Error('Failed to read file.'));
    };
    reader.readAsText(file);
  });
}
