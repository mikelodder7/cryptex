// A browser page that keeps cryptex keyrings in IndexedDB or localStorage.
//
// Build first:
//   wasm-pack build --target web --out-dir examples/web/pkg --no-default-features --features js
// Then serve this directory over http (not file://):
//   python3 -m http.server -d examples/web 8080
//
// OPFS keyrings are listed too, but opening one needs a worker: see worker.js.

import init, {
  Keyring,
  requestPersistentStorage,
  storedKeyrings,
} from "./pkg/cryptex.js";

const $ = (id) => document.getElementById(id);
const decoder = new TextDecoder();

/** The stores this page can open. OPFS needs the worker in worker.js. */
const STORES = ["indexeddb", "localstorage"];
/** Every store the page lists, including the one it cannot open here. */
const LISTED_STORES = [...STORES, "opfs"];

let keyring = null;
/** Where the open keyring lives, so the list can mark it. */
let current = null;

function show(message) {
  $("status").textContent = message;
}

function hint(message) {
  const item = document.createElement("li");
  item.className = "hint";
  item.textContent = message;
  return item;
}

function render(list, rows) {
  list.replaceChildren(...(rows.length ? rows : [hint("None stored.")]));
}

/** One entry per keyring, tagged with the store it lives in. */
function keyringRow(store, name) {
  const item = document.createElement("li");

  const tag = document.createElement("span");
  tag.className = "store";
  tag.textContent = store;
  item.append(tag);

  const button = document.createElement("button");
  button.className = "link";
  button.textContent = name;
  if (store === "opfs") {
    // A sync access handle is worker-only, so the page cannot open this.
    button.disabled = true;
    const note = document.createElement("span");
    note.className = "hint";
    note.textContent = "  opens in a worker";
    item.append(button, note);
    return item;
  }
  button.addEventListener("click", () =>
    guarded(async () => {
      $("name").value = name;
      $("store").value = store;
      await open();
      await refresh();
      const count = keyring.keys().length;
      show(`Opened "${name}" from ${store}; it holds ${count} key${count === 1 ? "" : "s"}.`);
    }),
  );
  item.append(button);

  if (current && current.store === store && current.name === name) {
    const open = document.createElement("span");
    open.className = "open";
    open.textContent = "(open)";
    item.append(open);
  }
  return item;
}

/** One entry per key in the open keyring, with its value. */
function keyRow(id) {
  const item = document.createElement("li");
  const name = document.createElement("code");
  name.textContent = id;
  const value = document.createElement("span");
  try {
    value.textContent = ` = ${decoder.decode(keyring.get(id))}`;
  } catch (error) {
    value.textContent = ` (${error.message})`;
  }
  item.append(name, value);
  return item;
}

async function refreshKeyrings() {
  const rows = [];
  for (const store of LISTED_STORES) {
    let names = [];
    try {
      names = await storedKeyrings({ store });
    } catch (error) {
      rows.push(hint(`${store}: ${error.message}`));
      continue;
    }
    if (!names.length) rows.push(hint(`${store}: none`));
    for (const name of names) rows.push(keyringRow(store, name));
  }
  render($("keyrings"), rows);
}

async function refreshKeys() {
  if (!keyring) {
    render($("keys"), [hint("Open a keyring to see its keys.")]);
    return;
  }
  render($("keys"), keyring.keys().map(keyRow));
}

async function refresh() {
  await refreshKeyrings();
  await refreshKeys();
}

/** Connection strings are `password=... salt=...`. */
function connection() {
  const password = $("password").value;
  if (!password) throw new Error("Enter a password first");
  // The connection string is whitespace-separated, so a value cannot contain
  // one; say so rather than passing the parser's byte offset to the user.
  if (/\s/.test(password)) {
    throw new Error("The password cannot contain spaces; the connection string is `password=<value> salt=<value>`");
  }
  return `password=${password} salt=cryptex-browser-example`;
}

async function open() {
  const name = $("name").value;
  const store = $("store").value;
  if (keyring) await keyring.close();
  keyring = await Keyring.open(connection(), name, { backend: "turso", store });
  current = { store, name };
  show(`Opened "${name}" from ${store}.`);
}

async function guarded(action) {
  try {
    await action();
  } catch (error) {
    show(`${error.message ?? error}`);
  }
}

$("open").addEventListener("click", () =>
  guarded(async () => {
    await open();
    await refresh();
    const count = keyring.keys().length;
    show(`Opened "${$("name").value}"; it holds ${count} key${count === 1 ? "" : "s"}.`);
  }),
);

$("persist").addEventListener("click", () =>
  guarded(async () => {
    const granted = await requestPersistentStorage();
    show(
      granted
        ? "The browser will not evict this origin's storage under pressure."
        : "The browser did not grant persistent storage; it may still evict the keyring.",
    );
  }),
);

$("set").addEventListener("click", () =>
  guarded(async () => {
    if (!keyring) throw new Error("Open the keyring first");
    await keyring.set($("id").value, new TextEncoder().encode($("value").value));
    await refreshKeys();
    show(`Stored "${$("id").value}". It is in ${current.store}, encrypted, before this line ran.`);
  }),
);

$("get").addEventListener("click", () =>
  guarded(async () => {
    if (!keyring) throw new Error("Open the keyring first");
    const bytes = keyring.get($("id").value);
    show(`${$("id").value} is ${decoder.decode(bytes)}`);
  }),
);

$("delete").addEventListener("click", () =>
  guarded(async () => {
    if (!keyring) throw new Error("Open the keyring first");
    await keyring.delete($("id").value);
    await refreshKeys();
    show(`Deleted "${$("id").value}".`);
  }),
);

$("export").addEventListener("click", () =>
  guarded(async () => {
    if (!keyring) throw new Error("Open the keyring first");
    const image = keyring.export();
    const text = Array.from(image, (b) => b.toString(16).padStart(2, "0")).join("");
    await navigator.clipboard.writeText(text);
    show(`Copied ${image.length} encrypted bytes to the clipboard.`);
  }),
);

// Show what the origin already holds before anything is opened.
await init();
await guarded(refresh);
