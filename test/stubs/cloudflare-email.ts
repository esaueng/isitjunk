/**
 * Test stub for the `cloudflare:email` built-in module (which only exists in the
 * Workers runtime). Mirrors the EmailMessage constructor so src/index.ts can be
 * imported and its email() handler exercised under vitest. Aliased in
 * vitest.config.ts.
 */
export class EmailMessage {
  constructor(
    public readonly from: string,
    public readonly to: string,
    public readonly raw: string,
  ) {}
}
