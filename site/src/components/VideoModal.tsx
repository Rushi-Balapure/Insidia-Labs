import { useId, useRef } from "react";

type Sources = {
  mp4: string;
  webm: string;
  vtt: string;
  poster: string;
};

export default function VideoModal({ sources }: { sources: Sources }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const dialogId = useId();

  function open() {
    const node = dialog.current;
    if (!node || node.open) return;
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
      <button className="btn ghost" type="button" onClick={open} aria-haspopup="dialog" aria-controls={dialogId}>
        Watch the film
      </button>
      <dialog
        ref={dialog}
        id={dialogId}
        className="film-dialog"
        aria-labelledby={titleId}
        onClose={() => dialog.current?.querySelector("video")?.pause()}
        onClick={(event) => {
          if (event.target !== event.currentTarget) return;
          const bounds = event.currentTarget.getBoundingClientRect();
          if (event.clientX < bounds.left || event.clientX > bounds.right ||
              event.clientY < bounds.top || event.clientY > bounds.bottom) close();
        }}
      >
        <div className="film-bar">
          <h2 id={titleId}>Insidia — the film</h2>
          <button className="btn ghost" type="button" onClick={close} autoFocus>
            Close
          </button>
        </div>
        <video controls playsInline poster={sources.poster} preload="metadata">
          <source src={sources.webm} type="video/webm" />
          <source src={sources.mp4} type="video/mp4" />
          <track kind="captions" src={sources.vtt} srcLang="en" label="English" default />
          <p>Your browser cannot play this video. <a href="/film">Read the transcript</a>.</p>
        </video>
        <p className="film-transcript"><a href="/film">Read the transcript and chapters</a></p>
      </dialog>
    </>
  );
}
