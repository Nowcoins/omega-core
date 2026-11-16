// Seals and opens vaults through the WebAssembly build's real JavaScript API
// (the Node target of the same .wasm), for scripts/cross-format.sh.
//
//   node cross-format.mjs open  <pkg-dir> <password> <vault-file>   # exits 1 unless it holds the reference phrase
//   node cross-format.mjs seal  <pkg-dir> <password> <vault-file>   # writes a vault of the reference phrase
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const [mode, pkgDir, password, file] = process.argv.slice(2);
const wasm = createRequire(import.meta.url)(resolve(pkgDir, 'nc_wallet_wasm.js'));

const ABANDON =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

if (mode === 'open') {
  const blob = new Uint8Array(readFileSync(file));
  const words = wasm.reveal_phrase(blob, password).join(' ');
  if (words !== ABANDON) throw new Error('the vault holds a different phrase');
  const engine = new wasm.WalletEngine();
  const key = engine.unlock_with_password(blob, password);
  const [eth] = engine.derive_accounts(0);
  if (key.length !== 32 || eth.address !== '0x9858EfFD232B4033E47d90003D41EC34EcaEda94') {
    throw new Error('unexpected account');
  }
  const facts = wasm.vault_facts(blob);
  console.log(`wasm opened ${file}: format ${facts.version}, ${facts.memoryKib} KiB, ${facts.iterations} passes, ${facts.lanes} lane`);
} else if (mode === 'seal') {
  const engine = new wasm.WalletEngine();
  engine.start_import(ABANDON, '');
  const blob = engine.seal_pending(password);
  writeFileSync(file, blob);
  console.log(`wasm sealed ${blob.length} bytes into ${file}`);
} else {
  throw new Error(`unknown mode ${mode}`);
}
