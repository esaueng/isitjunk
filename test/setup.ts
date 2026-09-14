/**
 * Vitest setup: expose Web Crypto as the global `crypto` binding.
 *
 * The Worker runtime (workerd) provides `crypto.subtle` globally, which
 * the Access JWT verifier uses. Vitest's Node sandbox does not
 * always surface the global `crypto` binding, so polyfill it from node:crypto.
 */
import { webcrypto } from 'node:crypto';

if (typeof (globalThis as { crypto?: unknown }).crypto === 'undefined') {
  (globalThis as { crypto?: unknown }).crypto = webcrypto;
}
