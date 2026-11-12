// app.js — Secure Render Pipeline (VULNERABLE STARTER)
//
// A feature does the same three things almost every page does: it fetches some
// data, parses the bytes into a value, and renders that value to the screen.
// fetch -> parse -> render. This starter collapses all three into one careless
// chain with no control at any boundary, so it is open to BOTH problems at once:
//
//   * insecure object handling (no try/catch, no shape check, no __proto__ guard)
//   * XSS (every field reaches the DOM through innerHTML, a markup sink)
//
// verify.js drives runPipeline(body, root) with a good body plus a set of
// malformed and hostile ones. Against this starter the attacks SUCCEED:
// a truncated body throws, a wrong-type field renders, a __proto__ payload
// pollutes Object.prototype, and a script string executes.

// The pipeline has three stages. Right now parse and render are jammed together
// with no checkpoint between them. Your job is to give each stage its own
// control: a defensive parse, then a render that uses safe sinks.

function parseStage(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    if (error instanceof SyntaxError) return null;
    throw error;
  }

  const keys = ["title", "body", "link", "richText"];
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !keys.every((key) => Object.hasOwn(parsed, key) && typeof parsed[key] === "string")
  ) {
    return null;
  }

  if (
    Object.hasOwn(parsed, "__proto__") ||
    Object.hasOwn(parsed, "constructor") ||
    Object.hasOwn(parsed, "prototype")
  ) {
    return null;
  }

  const data = Object.create(null);
  for (const key of keys) {
    data[key] = parsed[key];
  }
  return data;
}

function renderStage(data, root) {
  const title = document.createElement("h2");
  title.textContent = data.title;

  const body = document.createElement("p");
  body.textContent = data.body;

  const link = document.createElement("a");
  link.textContent = "Read more";
  let url;
  try {
    url = new URL(data.link);
  } catch (error) {
    if (!(error instanceof TypeError)) throw error;
  }
  if (url && ["http:", "https:", "mailto:"].includes(url.protocol)) {
    link.setAttribute("href", data.link);
  }

  const richText = document.createElement("div");
  richText.innerHTML = DOMPurify.sanitize(data.richText, { FORBID_TAGS: ["img"] });

  root.replaceChildren(title, body, link, richText);
}

// Shared application state the feature caches parsed responses into. A real app
// keeps state like this around between renders.
const appState = { lastArticle: {} };

// Recursively deep-merge `source` onto `target`. When `parseStage` returns an
// object that still carries a "__proto__" key, this merge writes onto
// Object.prototype — a prototype-pollution vector with no guard in front of it.
function deepMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]); // key === "__proto__" -> pollutes
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Orchestrator. A real version fetches the body first; the harness hands the
// raw body text in directly so the lab stays network-free.
function runPipeline(body, root) {
  const data = parseStage(body);
  if (data === null) {
    appState.lastArticle = {};
    root.replaceChildren();
    return;
  }

  appState.lastArticle = deepMerge({}, data);
  renderStage(data, root);
}

// Expose the entry point so the attack harness can drive it directly.
window.runPipeline = runPipeline;
