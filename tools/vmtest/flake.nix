{
  description = "Unified VM test environment for moontastik/ipparse + Lunatik (kernel modules)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  # lua5_5 is not in nixos-25.05; take it from unstable only (no other package
  # comes from there). Lunatik master builds against lua5.5.
  inputs.nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs, nixpkgs-unstable }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
        (system: f {
          inherit system;
          pkgs = nixpkgs.legacyPackages.${system};
          unstable = nixpkgs-unstable.legacyPackages.${system};
        });
    in
    {
      devShells = forAllSystems ({ pkgs, unstable, ... }: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Kernel build
            gcc
            gnumake
            flex
            bison
            bc
            elfutils
            libelf
            openssl
            perl
            ncurses
            pahole          # BTF
            ccache
            cpio
            zstd
            # virtme-ng (installed by ensure-vng.sh in a local venv) + VM
            python3
            iproute2        # virtme-ng-init runs `ip link set dev lo up`
            qemu_kvm
            util-linux      # script(1) wrapper for ttyless runs (CI)
            rustc           # builds virtme-ng-init (fast boot path)
            cargo
            # Lua toolchain (userspace tests + lunatik install)
            luajit
            lua5_4
            unstable.lua5_5
            # lunatik's Makefile invokes `lua5.4`/`lua5.5`; nixpkgs only ships `lua`
            (pkgs.writeShellScriptBin "lua5.4" ''exec ${pkgs.lua5_4}/bin/lua "$@"'')
            (pkgs.writeShellScriptBin "lua5.5" ''exec ${unstable.lua5_5}/bin/lua "$@"'')
            luajitPackages.moonscript
            # Misc
            git
            curl
            kmod
            # Lunatik master builds its eBPF loader against libbpf.
            libbpf
            pkg-config
          ];
          shellHook = ''
            # Nix binaries carry their rpath; an inherited LD_LIBRARY_PATH only
            # causes library-version clashes (e.g. qemu vs ambient openssl).
            unset LD_LIBRARY_PATH
            export VMTEST_DIR="$(git rev-parse --show-toplevel)/tools/vmtest"
            export PATH="$VMTEST_DIR/.venv/bin:$PATH"
            export KBUILD_BUILD_TIMESTAMP=""   # reproducible-ish kernel builds
          '';
        };
      });
    };
}
