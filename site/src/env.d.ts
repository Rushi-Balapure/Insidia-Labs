/// <reference types="astro/client" />

interface ImportMetaEnv {
  readonly PUBLIC_LEAD_ENDPOINT?: string;
  readonly PUBLIC_VERCEL_ANALYTICS_ID?: string;
  readonly VERCEL_ANALYTICS_ID?: string;
  readonly PUBLIC_VERCEL_ANALYTICS_DISABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
