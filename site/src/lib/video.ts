import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const publicRoot = fileURLToPath(new URL("../../public", import.meta.url));

export const howtoVideo = {
  mp4: "/video/howto.mp4",
  webm: "/video/howto.webm",
  vtt: "/video/howto.vtt",
  poster: "/video/howto.jpg",
};

export const filmVideo = {
  mp4: "/video/film.mp4",
  webm: "/video/film.webm",
  vtt: "/video/film.vtt",
  poster: "/video/film.jpg",
};

export function videoPublished(urlPath: string): boolean {
  return existsSync(join(publicRoot, urlPath.replace(/^\//, "")));
}
