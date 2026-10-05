/// <reference types="astro/client" />

interface ImportMetaEnv {
  readonly PUBLIC_LEAD_ENDPOINT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
