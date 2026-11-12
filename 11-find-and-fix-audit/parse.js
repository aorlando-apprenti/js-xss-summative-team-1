// parse.js — the data layer (VULNERABLE STARTER).
//
// This module turns server-style JSON into application values. It contains the
// app's DATA flaws (insecure parsing / object handling). Audit each function by
// tracing where the untrusted text comes from and what is done with the result.
//
// Entry points (driven by app.js and by verify.js):
//   parseConfig(text)         -> reads a fetched config blob
//   applySettings(text)       -> merges a fetched settings blob into defaults
//
// NOTE: there are no // TODO markers in this lab. Finding the flaws is the work.
// Trace each untrusted value to where it lands; the flaw is the unbroken path.

// App defaults that the fetched settings are merged on top of.
const DEFAULT_SETTINGS = { theme: "light", pageSize: 10 };

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseJsonObject(text, sourceName) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    console.error("Invalid JSON in " + sourceName + ".", error);
    return null;
  }

  if (!isPlainObject(parsed)) {
    console.error(sourceName + " must be a JSON object.");
    return null;
  }
  return parsed;
}

function hasUnsafeKeys(value) {
  if (value === null || typeof value !== "object") return false;

  for (const key of Object.keys(value)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      return true;
    }
    if (hasUnsafeKeys(value[key])) return true;
  }
  return false;
}

// Read a fetched config blob and hand back validated fields or reject it.
function parseConfig(text) {
  const cfg = parseJsonObject(text, "Config");
  if (!cfg) return null;

  if (typeof cfg.title !== "string" ||
      !Number.isInteger(cfg.maxItems) ||
      cfg.maxItems < 1) {
    console.error("Config must include a string title and a positive integer maxItems.");
    return null;
  }

  return {
    title: cfg.title,
    maxItems: cfg.maxItems,
  };
}

function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new TypeError("Refusing to merge an unsafe object key.");
    }

    const value = source[key];
    if (isPlainObject(value)) {
      if (!isPlainObject(target[key])) target[key] = {};
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

// Merge validated fetched settings on top of the app defaults.
function applySettings(text) {
  const parsed = parseJsonObject(text, "Settings");
  if (!parsed) return null;

  if (hasUnsafeKeys(parsed)) {
    console.error("Settings contain a forbidden object key.");
    return null;
  }

  const allowedKeys = ["theme", "pageSize"];
  if (Object.keys(parsed).some((key) => !allowedKeys.includes(key)) ||
      (Object.prototype.hasOwnProperty.call(parsed, "theme") &&
        typeof parsed.theme !== "string") ||
      (Object.prototype.hasOwnProperty.call(parsed, "pageSize") &&
        (!Number.isInteger(parsed.pageSize) || parsed.pageSize < 1))) {
    console.error("Settings contain unsupported fields or invalid values.");
    return null;
  }

  const settings = deepMerge({ ...DEFAULT_SETTINGS }, parsed);
  return settings;
}

// Expose entry points for app.js and the harness.
window.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
window.parseConfig = parseConfig;
window.applySettings = applySettings;
