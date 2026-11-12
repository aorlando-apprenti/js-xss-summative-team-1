// render.js — the view layer (VULNERABLE STARTER).
//
// This module writes values to the DOM. It contains the app's RENDER flaws
// (XSS). Audit each function by tracing the untrusted value to the sink it
// reaches: a markup sink (innerHTML / insertAdjacentHTML), a URL sink (href),
// or a code sink (an inline on* attribute).
//
// Entry points (driven by app.js and by verify.js):
//   renderSearch(term, el)      -> echoes the search term
//   renderMembers(members, el)  -> renders the team-member list
//
// A member looks like: { name, bio, website }
//   name    -> shown as the heading and used by the "say hi" button
//   bio     -> a short blurb that may contain light formatting
//   website -> the member's profile link

// Echo the search term into the results banner.
function renderSearch(term, el) {
  el.replaceChildren();

  const label = document.createTextNode("Showing results for: ");
  const strong = document.createElement("strong");
  strong.textContent = term;
  el.append(label, strong);
}

// Render one member card and append it to the list container.
function renderMember(member, listEl) {
  const card = document.createElement("div");
  card.className = "member";

  // Heading: the member name.
  const h = document.createElement("h3");
  h.textContent = member.name; // (this one is already safe — note it in your audit)
  card.appendChild(h);

  // Bios support only light formatting; sanitize before using the markup sink.
  const bio = document.createElement("p");
  if (typeof member.bio === "string") {
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === "function") {
      bio.innerHTML = window.DOMPurify.sanitize(member.bio, {
        ALLOWED_TAGS: ["em", "strong"],
        ALLOWED_ATTR: [],
      });
    } else {
      bio.textContent = member.bio;
    }
  }
  card.appendChild(bio);

  // Only absolute or relative URLs that resolve to HTTP(S) are navigable.
  if (typeof member.website === "string") {
    let profileUrl;
    try {
      const parsedUrl = new URL(member.website, document.baseURI);
      if (parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:") {
        profileUrl = parsedUrl.href;
      }
    } catch (error) {
      console.warn("Skipping invalid member profile URL.", error);
    }

    if (profileUrl) {
      const link = document.createElement("a");
      link.href = profileUrl;
      link.textContent = "Profile";
      card.appendChild(link);
    }
  }

  const btn = document.createElement("button");
  btn.textContent = "Say hi";
  btn.addEventListener("click", () => {
    alert("hi " + member.name);
  });
  card.appendChild(btn);

  listEl.appendChild(card);
}

// Render the whole member list.
function renderMembers(members, el) {
  el.replaceChildren();
  for (const m of members) renderMember(m, el);
}

// Expose entry points for app.js and the harness.
window.renderSearch = renderSearch;
window.renderMembers = renderMembers;
