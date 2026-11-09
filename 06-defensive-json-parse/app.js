// app.js — the profile handler under test.
//
// A profile page fetches a user record and renders it. A resolved fetch only
// tells you bytes arrived; it tells you nothing about whether those bytes form
// the object this code expects. This starter trusts the parsed shape completely:
// it parses the body and reaches straight into `data.user.name` and
// `data.user.roles` without a single check.
//
// That works the first hundred times, while the API returns the shape you
// assumed. It breaks the moment the API returns an error envelope, a proxy
// truncates the stream, or a field comes back as the wrong type — the handler
// throws inside the render path and the page goes blank, or it mis-uses a
// wrongly typed value and feeds corrupt data downstream toward a DOM write.
//
// `verify.js` runs a well-formed body plus three bad ones through loadProfile().
// In this starter the bad bodies make it throw or return a corrupt profile —
// the harness reports the vulnerability as REPRODUCED.

// A tiny stand-in for a fetch Response, so this lab stays framework- and
// network-free. `text()` returns the raw body; `json()` parses it (and throws
// on malformed JSON, exactly like the real thing).
export function makeResponse(body) {
  return {
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

// The naive handler. No safe-parse wrapper, no shape check, no bounds check.
export async function loadProfile(response) {
  let body;
  try {
    body = await response.text();
  }
  catch (e) {
    return {ok: false, reason: "body-read-failed"};
  }

  if (typeof body !== "string") {
    return {ok: false, reason: "body-not-string"};
  }
  if (body.trim().length === 0) {
    return {ok: false, reason: "body-empty"};
  }

  let data;
  try {
    data = JSON.parse(body);
  }
  catch (e) {
    return {ok: false, reason: "invalid-json"};
  }

  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return {ok: false, reason: "invalid-root"};
  }
  if (!Object.hasOwn(data, "user")) {
    return {ok: false, reason: "missing-user"};
  }

  const user = data.user;
  if (user === null || typeof user !== "object" || Array.isArray(user)) {
    return {ok: false, reason: "invalid-user"};
  }
  if (!Object.hasOwn(user, "id")) {
    return {ok: false, reason: "missing-id"};
  }
  if (!Object.hasOwn(user, "name")) {
    return {ok: false, reason: "missing-name"};
  }
  if (!Object.hasOwn(user, "roles")) {
    return {ok: false, reason: "missing-roles"};
  }

  const id = user.id;
  const name = user.name;
  const roles = user.roles;

  if (typeof id !== "number") {
    return {ok: false, reason: "invalid-id-type"};
  }
  if (typeof name !== "string") {
    return {ok: false, reason: "invalid-name-type"};
  }
  if (!Array.isArray(roles) || !roles.every((role) => typeof role === "string")) {
    return {ok: false, reason: "invalid-roles-type"};
  }

  if (name.length > 100) {
    return {ok: false, reason: "name-too-long"};
  }

  const allowedRoles = new Set(["admin"]);
  if (!roles.every((role) => allowedRoles.has(role))) {
    return {ok: false, reason: "invalid-roles"};
  }

  return {ok: true, profile: {id, name, roles}};
}