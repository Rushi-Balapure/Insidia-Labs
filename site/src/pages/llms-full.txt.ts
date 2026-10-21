import type { APIRoute } from "astro";
import guide from "../../../docs/public/llms.txt?raw";

const documents = import.meta.glob<string>("../../../docs/src/content/docs/**/*.md", {
  query: "?raw", import: "default", eager: true,
});

export const GET: APIRoute = ({ site }) => {
  const sections = Object.entries(documents)
  .filter(([file]) => !file.endsWith("/404.md"))
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([file, markdown]) => {
    const slug = file.split("/content/docs/")[1].replace(/\.md$/, "");
    const title = markdown.match(/^title: (.+)$/m)?.[1] ?? slug;
    const body = markdown.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, "").trim();
    return `# ${title}\n\nSource: ${new URL(`/docs/${slug}/`, site).href}\n\n${body}`;
  });

  return new Response([guide.trim(), ...sections].join("\n\n---\n\n"), {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
};
