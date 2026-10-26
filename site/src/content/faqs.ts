import { docsAgent, docsTests } from "../lib/paths";

export interface FaqLink {
  href: string;
  before: string;
  label: string;
}

export interface Faq {
  id: string;
  question: string;
  answer: string;
  link?: FaqLink;
}

export const faqs: Faq[] = [
  {
    id: "test",
    question: "What can I test?",
    answer: "AI apps, agents, web apps, and APIs. Insidia checks areas such as prompt injection, data leakage, and application vulnerabilities. Available checks depend on your target and installed engines. Some checks only work on the project's test apps.",
    link: { href: docsTests, before: "See", label: "what it tests" },
  },
  {
    id: "data",
    question: "Does my scan data leave my machine?",
    answer: "The CLI runs locally and sends no telemetry. A scan contacts your configured target and any model endpoint you choose. Reports are saved on your machine.",
  },
  {
    id: "model",
    question: "Do I need an API key or a model?",
    answer: "You can run the L1 baseline without a model or model API key. Checks that need a model are skipped unless you configure one. External engines may need additional setup.",
  },
  {
    id: "skill",
    question: "How do I use the agent skill?",
    answer: "Run npx skills add Rushi-Balapure/Insidia-Labs in your project and select your agent. Then ask it to use Insidia on your running app. The skill guides setup, scanning, and report review. You confirm which hosts it may test.",
    link: { href: docsAgent, before: "Follow the", label: "agent setup guide" },
  },
  {
    id: "deployed",
    question: "Can I test a deployed app?",
    answer: "Yes, if you own it or have permission to test it. Add the host to insidia.yaml with authorized: true and confirm the scan with --yes. Start on localhost or staging while you set up your checks.",
  },
  {
    id: "cost",
    question: "What does it cost?",
    answer: "The CLI and agent skill are free. You do not need an Insidia account. Any paid model services you configure have their own costs. Insidia Cloud is in development; pricing has not been announced.",
  },
];
