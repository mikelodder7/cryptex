// A browser page that keeps a cryptex keyring in IndexedDB.
//
// Build first:
//   wasm-pack build --target web --out-dir examples/web/pkg -- --no-default-features --features js
// Then serve this directory over http (not file://):
//   python3 -m http.server -d examples/web 8080

import init, { Keyring, requestPersistentStorage } from "./pkg/cryptex.js";

const $ = (id) => document.getElementById(id);

let keyring = null;

function show(message) {
  $("status").textContent = message;
}

/** Connection strings are `password=... salt=...`. */
function connection() {
  const password = $("password").value;
  if (!password) throw new Error("Enter a password first");
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
    const ids = [];
    // Reading a secret that is not there is an error, not an empty value.
    for (const id of ["api-token"]) {
      try {
        keyring.get(id);
        ids.push(id);
      } catch (error) {
        if (!String(error).startsWith("ItemNotFound")) throw error;
      }
    }
    if (ids.length) show(`Opened "${$("name").value}"; it holds ${ids.join(", ")}.`);
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
