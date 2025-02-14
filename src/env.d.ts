/// <reference types="astro/client" />
/// <reference types="@cloudflare/workers-types" />

declare namespace App {
  interface Locals {
    runtime: {
      env: {
        'STATIC_SALT': string;
        'HMAC_KEY': string;
        'QR_BASE_URL': string;
      }
    }
  }
}