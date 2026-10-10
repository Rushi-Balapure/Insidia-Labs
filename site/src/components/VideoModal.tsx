import { useRef } from "react";

type Sources = {
  mp4: string;
  webm: string;
  vtt: string;
  poster: string;
};

export default function VideoModal({ sources }: { sources: Sources }) {
  const dialog = useRef<HTMLDialogElement>(null);

  function open() {
    const node = dialog.current;
    if (!node) return;
    node.showModal();
    const video = node.querySelector("video");
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (video && !reduce) {
      video.muted = true;
      void video.play().catch(() => undefined);
    }
  }

  function close() {
    const node = dialog.current;
    node?.querySelector("video")?.pause();
    node?.close();
  }

  return (
    <>
      <button className="btn ghost" type="button" onClick={open} aria-haspopup="dialog">
        Watch the film
      </button>
      <dialog
        ref={dialog}
        className="film-dialog"
        aria-labelledby="howto-title"
        onClose={() => dialog.current?.querySelector("video")?.pause()}
        onClick={(event) => {
          if (event.target === dialog.current) close();
        }}
      >
        <div className="film-bar">
          <h2 id="howto-title">Insidia</h2>
          <button className="btn ghost" type="button" onClick={close}>
            Close
          </button>
        </div>
        <video controls playsInline poster={sources.poster} preload="metadata">
          <source src={sources.webm} type="video/webm" />
          <source src={sources.mp4} type="video/mp4" />
          <track kind="captions" src={sources.vtt} srcLang="en" label="English" default />
        </video>
      </dialog>
    </>
  );
}
