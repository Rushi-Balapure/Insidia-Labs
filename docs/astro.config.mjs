import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://docs.insidialabs.com",
  integrations: [
    starlight({
      title: "Insidia Labs",
      description: "Install the Insidia CLI, scan a local app, and read the report.",
      customCss: ["./src/styles/custom.css"],
      logo: { src: "./src/assets/mark.svg" },
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/Rushi-Balapure/Insidia-Labs" },
      ],
      sidebar: [
        {
          label: "Start",
          items: [
            { label: "Overview", link: "/" },
            { label: "Install", slug: "start/install" },
            { label: "Quickstart", slug: "start/quickstart" },
            { label: "Scope", slug: "start/scope" },
            { label: "Use a coding agent", slug: "start/agent" },
          ],
        },
        {
          label: "Concepts",
          items: [
            { label: "What it tests", slug: "concepts/what-it-tests" },
            { label: "Benchmark", slug: "concepts/benchmark" },
            { label: "Engines", slug: "concepts/engines" },
            { label: "Report", slug: "concepts/report" },
          ],
        },
        {
          label: "Reference",
          items: [{ label: "CLI", slug: "reference/cli" }],
        },
        {
          label: "Insidia Cloud",
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
