import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://insidialabs.com",
  base: "/docs",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "Insidia Labs",
      description: "Install the Insidia CLI, scan a local app, and read the report.",
      customCss: ["./src/styles/custom.css"],
      logo: { src: "./src/assets/mark.svg" },
      components: { SiteTitle: "./src/components/SiteTitle.astro" },
      editLink: { baseUrl: "https://github.com/Rushi-Balapure/Insidia-Labs/edit/main/docs/" },
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/Rushi-Balapure/Insidia-Labs" },
      ],
      sidebar: [
        {
          label: "Getting started",
          items: [
            { label: "Overview", link: "/" },
            { label: "Install", slug: "start/install" },
            { label: "Your first scan", slug: "start/quickstart" },
            { label: "Use a coding agent", slug: "start/agent" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Read a report", slug: "concepts/report" },
            { label: "Install engines", slug: "concepts/engines" },
            { label: "Run in CI", slug: "guides/ci" },
            { label: "Troubleshooting", slug: "guides/troubleshooting" },
          ],
        },
        {
          label: "Concepts",
          items: [
            { label: "What it tests", slug: "concepts/what-it-tests" },
            { label: "Benchmark", slug: "concepts/benchmark" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI", slug: "reference/cli" },
            { label: "Configuration", slug: "start/config" },
            { label: "Scope", slug: "start/scope" },
          ],
        },
        {
          label: "Insidia Cloud (planned)",
          items: [{ label: "Hosted attacker", slug: "cloud" }],
        },
        {
          label: "Security",
          items: [{ label: "Data handling", slug: "security/data" }],
        },
      ],
    }),
  ],
});
