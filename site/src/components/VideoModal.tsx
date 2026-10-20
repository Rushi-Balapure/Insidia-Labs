import { useId, useRef } from "react";

type Sources = {
  mp4: string;
  webm: string;
  vtt: string;
  poster: string;
  transcript?: string;
};

export default function VideoModal({ sources, thumbnail = false, label = "Watch the film", title = "Insidia — the film" }: {
  sources: Sources;
  thumbnail?: boolean;
  label?: string;
  title?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const dialogId = useId();
  const transcript = sources.transcript ?? "/film";

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
      <button className={thumbnail ? "video-preview" : "btn ghost"} type="button" onClick={open} aria-label={label} aria-haspopup="dialog" aria-controls={dialogId}>
        {thumbnail ? <>
          <img src={sources.poster} alt="" width="960" height="540" loading="lazy" />
          <span className="video-preview-play" aria-hidden="true">▶</span>
          <span className="video-preview-label">{label} <span aria-hidden="true">↗</span></span>
        </> : label}
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
          <h2 id={titleId}>{title}</h2>
          <button className="btn ghost" type="button" onClick={close} autoFocus>
            Close
          </button>
        </div>
        <video controls playsInline poster={sources.poster} preload="metadata">
          <source src={sources.webm} type="video/webm" />
          <source src={sources.mp4} type="video/mp4" />
          <track kind="captions" src={sources.vtt} srcLang="en" label="English" default />
          <p>Your browser cannot play this video. <a href={transcript}>Read the transcript</a>.</p>
        </video>
        <p className="film-transcript"><a href={transcript}>Read the transcript</a></p>
      </dialog>
    </>
  );
}
