import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

export default defineConfig({
  integrations: [
    starlight({
      title: "Insidia Labs",
      social: [],
      sidebar: [{ label: "Start", autogenerate: { directory: "." } }],
    }),
  ],
});
