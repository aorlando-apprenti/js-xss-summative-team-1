// app.js — Comment-with-profile-card widget (VULNERABLE STARTER).
//
// A realistic user-generated feature: parse a comment response, then render an
// author, a timestamp, comment text, a linked profile, and an optional
// rich-text body. As shipped it has only thin, partial defenses — a single
// gatekeeper here and there — so a single bug exposes the whole feature.
//
// Your job is to layer FIVE independent controls so that no single bug
// compromises the widget:
//   1. validation  — schema, types, and bounded lengths at parse
//   2. object-handling — a prototype-pollution guard before building the object
//   3. safe sinks  — textContent for author / timestamp / text
//   4. sanitization — DOMPurify for the rich-text body ONLY
//   5. URL         — scheme allow-listing for the profile link + addEventListener
//
// verify.js runs a scripted attack set and an independence test. Against this
// starter the attacks SUCCEED (script executes, a javascript: link is written,
// Object.prototype is polluted, an over-long / malformed body slips through).

const MAX_LEN = 2000;
const POLLUTION_KEYS = ["__proto__", "constructor", "prototype"];
const SAFE_SCHEMES = ["http:", "https:", "mailto:"];

// Field defaults a parsed comment is normalized onto.
const COMMENT_DEFAULTS = { author: "", timestamp: "", text: "", website: "", richText: "" };

// ---- Parse: turn a comment response body into a comment object. ----
function validateComment(text) {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }

  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;

  if (POLLUTION_KEYS.some((key) => Object.hasOwn(raw, key))) return null;

  const comment = Object.create(null);
  for (const field of Object.keys(COMMENT_DEFAULTS)) {
    if (!Object.hasOwn(raw, field) ||
        typeof raw[field] !== "string" ||
        raw[field].length > MAX_LEN) {
      return null;
    }
    comment[field] = raw[field];
  }

  return comment;
}

// Return an allowed href, or null. (Helper for the URL layer once you build it.)
function safeUrl(value) {
  try {
    const u = new URL(value, location.origin);
    return SAFE_SCHEMES.includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}

// ---- Render: write the comment to the DOM. ----
function renderComment(c, root) {
  const card = document.createElement("div");
  card.className = "comment";

  const author = document.createElement("span");
  author.className = "author";
  author.textContent = c.author;
  card.appendChild(author);

  const timestamp = document.createElement("time");
  timestamp.textContent = c.timestamp;
  card.appendChild(timestamp);

  const text = document.createElement("p");
  text.textContent = c.text;
  card.appendChild(text);

  const link = document.createElement("a");
  link.textContent = c.author;
  const href = safeUrl(c.website);
  if (href !== null) link.setAttribute("href", href);
  link.addEventListener("click", () => openProfile(c.author));
  card.appendChild(link);

  const rich = document.createElement("div");
  rich.innerHTML = DOMPurify.sanitize(c.richText, { FORBID_TAGS: ["img"] });
  card.appendChild(rich);

  root.append(card);
}

// A trivial profile opener referenced by the inline handler above.
function openProfile(name) {
  console.log("open profile:", name);
}

// Expose the entry points so the attack harness can drive them directly.
window.validateComment = validateComment;
window.renderComment = renderComment;
window.openProfile = openProfile;
