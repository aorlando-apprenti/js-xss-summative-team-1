// app.js — VULNERABLE starter.
//
// renderComment(comment, host) renders a rich-text comment. Comments may
// legitimately contain <b>, <i>, <a>, and <ul>, so the feature renders them as
// HTML — which means textContent is NOT an option here (it would show the tags
// as literal characters and break the feature).
//
// As written, the untrusted comment.html is assigned straight to innerHTML, so a
// comment like `<img src=x onerror=...>` or `<a href="javascript:...">` executes
// on render. Open index.html and read the verdict in #result: the payload
// battery will report FAIL.
//
// YOUR TASK: sanitize comment.html so it is safe to render, while preserving
// benign formatting (bold, italics, safe links, lists). Sanitization is an XSS
// OUTPUT defense — it runs at the render boundary, on the exact string you
// assign, with nothing concatenated afterward. Two ways to do it:
//
//   - Vetted library (the professional default): DOMPurify is loaded by
//     index.html, so you can call DOMPurify.sanitize(...). Prefer a strict
//     allow-list config (ALLOWED_TAGS / ALLOWED_ATTR).
//   - Manual allow-list (teaching): parse with DOMParser into a detached, inert
//     tree, drop any tag not on a small allow-list, strip any attribute not
//     permitted, re-validate href schemes, then serialize and assign that string.


function sanitizeHtml(html) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");

  const allowedTags = ['b', 'i', 'a', 'ul', 'li'];

  function sanitize(node) {
    for (let i = node.childNodes.length - 1; i>= 0; i--) {
      const child = node.childNodes[i];
      if (child.nodeType === Node.ELEMENT_NODE) {
        if(!allowedTags.includes(child.tagName.toLowerCase())) {
          child.remove();
        } else {
          const attrs = Array.from(child.attributes);
          for (const attr of attrs) {
            if (child.tagName.toLowerCase() === "a" && attr.name.toLowerCase() === "href") {
              const val = attr.value.trim().toLowerCase();
              if (val.startsWith("javascript:") || val.startsWith("data:") || val.startsWith("vbscript:")) {
                child.removeAttribute(attr.name);
            }
          } else {
            child.removeAttribute(attr.name);
          }
        }
        sanitize(child);
      }
    } else if (child.nodeType !== Node.TEXT_NODE) {
      child.remove();
    }
  }
}

sanitize(doc.body);
return doc.body.innerHTML;
}


function renderComment(comment, host) {
  const el = document.createElement("div");
  el.className = "comment";

  const cleanHtml = sanitizeHtml(comment.html);

  el.innerHTML = cleanHtml;

    


  // DONE: Sanitize comment.html (DOMPurify with a strict config, or a manual
  //       allow-list sanitizer) and assign the cleaned string here — with no
  //       concatenation after the sanitizer runs.
  // VULNERABLE: untrusted HTML straight to the sink

  host.appendChild(el);
}

window.renderComment = renderComment;
