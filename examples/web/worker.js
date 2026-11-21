// A dedicated worker that keeps a cryptex keyring in the origin private file
// system (OPFS).
//
// OPFS sync access handles only exist in a worker, and deriving the key with
// Argon2 blocks whichever thread it runs on, so this is where the keyring
// belongs.
//
// Build first:
//   wasm-pack build --target web --out-dir examples/web/pkg -- --no-default-features --features js
// Then, from the page:
//   const worker = new Worker("./worker.js", { type: "module" });
//   worker.postMessage({ id: 1, op: "open", password: "...", name: "example" });

import init, { Keyring } from "./pkg/cryptex.js";

let ready = null;
let keyring = null;

async function open({ password, name }) {
  // The connection string is whitespace-separated, so a password that holds a
  // space, or a ` salt=` of its own, would change how it is parsed.
  if (!password || /\s/.test(password)) {
    throw new Error("the password must be non-empty and cannot contain spaces");
  }
  ready ??= init();
  await ready;
  if (keyring) await keyring.close();
  keyring = await Keyring.open(
    `password=${password} salt=cryptex-browser-example`,
    name,
    { backend: "turso", store: "opfs" },
  );
}

self.addEventListener("message", async (event) => {
  const { id, op, ...args } = event.data;
  try {
    switch (op) {
      case "open":
        await open(args);
        postMessage({ id, ok: true });
        break;
      case "set":
        await keyring.set(args.key, new TextEncoder().encode(args.value));
        postMessage({ id, ok: true });
        break;
      case "get":
        postMessage({
          id,
          ok: true,
          value: new TextDecoder().decode(keyring.get(args.key)),
        });
        break;
      case "delete":
        await keyring.delete(args.key);
        postMessage({ id, ok: true });
        break;
      case "close":
        await keyring.close();
        keyring = null;
        postMessage({ id, ok: true });
        break;
      default:
        throw new Error(`unknown operation ${op}`);
    }
  } catch (error) {
    postMessage({ id, ok: false, error: String(error) });
  }
});
