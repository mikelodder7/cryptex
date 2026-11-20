// A browser page that keeps a cryptex keyring in IndexedDB.
//
// Build first:
//   wasm-pack build --target web --out-dir examples/web/pkg -- --no-default-features --features js
// Then serve this directory over http (not file://):
//   python3 -m http.server -d examples/web 8080

import init, {
  Keyring,
  requestPersistentStorage,
  storedKeyrings,
} from "./pkg/cryptex.js";

const $ = (id) => document.getElementById(id);
const decoder = new TextDecoder();

let keyring = null;

function show(message) {
  $("status").textContent = message;
}

function render(list, empty, rows) {
  list.replaceChildren();
  if (!rows.length) {
    const item = document.createElement("li");
    item.className = "hint";
    item.textContent = empty;
    list.append(item);
    return;
  }
  list.append(...rows);
}

/** One entry per keyring in IndexedDB; clicking it opens that keyring. */
function keyringRow(name) {
  const item = document.createElement("li");
  const button = document.createElement("button");
  button.className = "link";
  button.textContent = name;
  button.addEventListener("click", () =>
    guarded(async () => {
      $("name").value = name;
      await open();
      await refresh();
    }),
  );
  item.append(button);
  if (keyring && name === $("name").value) {
    const open = document.createElement("span");
    open.className = "open";
    open.textContent = "  (open)";
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
  const names = await storedKeyrings();
  render($("keyrings"), "None stored yet.", names.map(keyringRow));
}

async function refreshKeys() {
  if (!keyring) {
    render($("keys"), "Open a keyring to see its keys.", []);
    return;
  }
  render($("keys"), "This keyring holds no keys.", keyring.keys().map(keyRow));
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
  await init();
  if (keyring) await keyring.close();
  keyring = await Keyring.open(connection(), $("name").value, {
    backend: "turso",
    store: "indexeddb",
  });
  show(`Opened "${$("name").value}".`);
}

async function guarded(action) {
  try {
    await action();
  } catch (error) {
    show(`${error}`);
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
    await init();
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
    show(`Stored "${$("id").value}". It is on disk, encrypted, before this line ran.`);
  }),
);

$("get").addEventListener("click", () =>
  guarded(async () => {
    if (!keyring) throw new Error("Open the keyring first");
    const bytes = keyring.get($("id").value);
    show(`${$("id").value} is ${new TextDecoder().decode(bytes)}`);
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
