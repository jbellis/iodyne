{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "diskwatch";
  # Keep in sync with Cargo.toml's `version` on every release — the Nix
  # derivation label otherwise drifts from the actual source contents.
  version = "0.1.2";

  src = lib.cleanSource ./.;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "Single-screen, read-only disk IO, latency, topology, and health TUI";
    homepage = "https://github.com/matthart1983/diskwatch";
    license = lib.licenses.mit;
    mainProgram = "diskwatch";
  };
}
