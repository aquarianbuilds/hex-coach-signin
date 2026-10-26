// Hex Coach consent page logic. A file of its own, because the page's content security policy allows no inline script.
(() => {
  // Filled in by web/signin/publish.sh from apps/mobile/.env. The publishable key is public by design.
  const SUPABASE_URL = "https://ibxszbqmvzbhokxlehwq.supabase.co";
  const SUPABASE_KEY = "sb_publishable_Jg3ORNjSYm2uVC0D675KaA_TGpvaZVy";
  // Never work inside a frame: a framed page could hide the Allow button under something else.
  if (window.top !== window.self) { document.getElementById("framed").hidden = false; return; }
  document.getElementById("card").hidden = false;

  // Only the real Claude and ChatGPT addresses (and Claude Code on this computer) can receive access.
  const TRUSTED = [
    (u) => u.protocol === "https:" && (u.hostname === "claude.ai" || u.hostname === "claude.com"),
    (u) => u.protocol === "https:" && (u.hostname === "chatgpt.com" || u.hostname === "chat.openai.com"),
    (u) => u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1"),
  ];
  const trusted = (address) => {
    try { const u = new URL(address); return TRUSTED.some((ok) => ok(u)); } catch { return false; }
  };
  const go = (address) => {
    if (!trusted(address)) { fail("This request does not go back to Claude or ChatGPT, so Hex Coach stopped it."); return; }
    location.href = address;
  };
  const $ = (id) => document.getElementById(id);
  const show = (id, on) => { $(id).hidden = !on; };
  const say = (text) => { $("status").textContent = text; };
  const fail = (text) => { $("error").textContent = text; show("error", true); };

  const query = new URLSearchParams(location.search);
  const authorizationId = query.get("authorization_id");
  // A tab opened from the sign-in email link. The answer must go back from the tab that Claude or ChatGPT
  // opened, so this tab only signs in; the first tab gets the sign-in and continues there.
  const fromEmailLink = query.has("code");
  if (!authorizationId) { say("This page opens when Claude or ChatGPT asks to connect to Hex Coach."); return; }

  const client = supabase.createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { flowType: "pkce", persistSession: true, detectSessionInUrl: true } });
  let email = "";
  let started = false;

  const consent = async () => {
    if (started) return;
    started = true;
    show("email-form", false); show("code-form", false);
    say("Checking the request…");
    const { data, error } = await client.auth.oauth.getAuthorizationDetails(authorizationId);
    if (error) { fail("This request has expired or is not valid. Start the connection again in Claude or ChatGPT."); return; }
    if (!("authorization_id" in data)) { go(data.redirect_url); return; }
    if (!trusted(data.redirect_uri)) { say(""); fail("This request does not come from Claude or ChatGPT, so Hex Coach stopped it. Do not allow it."); return; }
    say("");
    $("title").textContent = "Connect " + (data.client?.name || "an app");
    $("consent-text").textContent = (data.client?.name || "This app") + " asks to use your Hex Coach data.";
    $("consent-where").textContent = "Access goes back to: " + new URL(data.redirect_uri).host;
    $("scopes").replaceChildren(...String(data.scope || "").split(" ").filter(Boolean).map((s) => Object.assign(document.createElement("li"), { textContent: s })));
    show("consent", true);
  };

  const decide = async (allow) => {
    $("allow").disabled = true; $("deny").disabled = true;
    const call = allow ? client.auth.oauth.approveAuthorization(authorizationId) : client.auth.oauth.denyAuthorization(authorizationId);
    const { data, error } = await call;
    if (error) { fail("Hex Coach could not save your answer. Try again."); $("allow").disabled = false; $("deny").disabled = false; return; }
    say(allow ? "Connected. Going back…" : "Denied. Going back…");
    go(data.redirect_url);
  };
  $("allow").onclick = () => decide(true);
  $("deny").onclick = () => decide(false);

  $("email-form").onsubmit = async (event) => {
    event.preventDefault();
    email = $("email").value.trim().toLowerCase();
    const { error } = await client.auth.signInWithOtp({ email, options: { shouldCreateUser: false, emailRedirectTo: location.href } });
    if (error) { fail(error.status === 429 ? "Too many sign-in emails. Try again later." : "Hex Coach could not send the email. Check the address and try again."); return; }
    show("error", false); show("email-form", false); show("code-form", true);
    say("Email sent to " + email + ".");
  };

  $("code-form").onsubmit = async (event) => {
    event.preventDefault();
    const token = $("code").value.replace(/\s/g, "");
    const { error } = await client.auth.verifyOtp({ email, token, type: "email" });
    if (error) { fail("This code is wrong or too old. Check it, or send a new one."); return; }
    show("error", false);
    await consent();
  };

  client.auth.onAuthStateChange((event, session) => {
    if (event === "SIGNED_IN" && session && !fromEmailLink) setTimeout(consent, 0);
  });

  client.auth.getSession().then(({ data }) => {
    if (fromEmailLink) {
      if (data.session) say("You are signed in. Go back to the first Hex Coach tab and select Allow there. You can close this tab. If you closed the first tab, start the connection again in Claude or ChatGPT.");
      else { say(""); fail("This sign-in link has expired or was used. Go back to the first Hex Coach tab and send a new email."); }
      return;
    }
    if (data.session) { consent(); return; }
    say("Sign in with the email you use in Hex Coach.");
    show("email-form", true);
  });
})();
