import { useEffect, useId, useRef } from "react";

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
  const stage = useRef<HTMLDivElement>(null);
  const inlineVideo = useRef<HTMLVideoElement>(null);
  const titleId = useId();
  const dialogId = useId();
  const transcript = sources.transcript ?? "/film";

  useEffect(() => {
    const node = stage.current;
    const video = inlineVideo.current;
    if (!node || !video) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    const observer = new IntersectionObserver(([entry]) => {
      if (!entry?.isIntersecting) {
        video.pause();
        return;
      }
      video.muted = false;
      void video.play().catch(() => {
        video.muted = true;
        void video.play().catch(() => undefined);
      });
    }, { threshold: 0.55 });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  function open() {
    const node = dialog.current;
    if (!node || node.open) return;
    node.showModal();
    const video = node.querySelector("video");
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (video && !reduce) {
      video.muted = false;
      void video.play().catch(() => {
        if (!video) return;
        video.muted = true;
        void video.play().catch(() => undefined);
      });
    }
  }

  function close() {
    const node = dialog.current;
    node?.querySelector("video")?.pause();
    node?.close();
  }

  if (thumbnail) {
    return (
      <div className="video-stage" ref={stage}>
        <video
          ref={inlineVideo}
          className="video-inline"
          controls
          playsInline
          poster={sources.poster}
          preload="metadata"
          aria-label={label}
        >
          <source src={sources.mp4} type="video/mp4" />
          <source src={sources.webm} type="video/webm" />
          <p>Your browser cannot play this video. <a href={transcript}>Read the transcript</a>.</p>
        </video>
      </div>
    );
  }

  return (
    <>
      <button className="btn ghost" type="button" onClick={open} aria-label={label} aria-haspopup="dialog" aria-controls={dialogId}>
        {label}
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
          <source src={sources.mp4} type="video/mp4" />
          <source src={sources.webm} type="video/webm" />
          <p>Your browser cannot play this video. <a href={transcript}>Read the transcript</a>.</p>
        </video>
        <p className="film-transcript"><a href={transcript}>Read the transcript</a></p>
      </dialog>
    </>
  );
}
