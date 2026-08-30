{
  description = "Pinned system toolchain for github.com/mindclade/github-config";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems =
        function:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = function system (import nixpkgs { inherit system; });
          }) systems
        );
    in
    {
      packages = forAllSystems (
        system: pkgs:
        let
          opaTarget =
            {
              aarch64-darwin = {
                asset = "opa_darwin_arm64";
                hash = "sha256-K4BdR2CZ+Bgo4KckZvI7fF9wNejlGCP14e88v08jIc4=";
              };
              x86_64-linux = {
                asset = "opa_linux_amd64";
                hash = "sha256-SBTKr4kGK5kp5zc8dF6xtzvoqjR75h2gZJH2j+kQJFs=";
              };
            }
            .${system};
          opa = pkgs.runCommand "opa-1.20.1" { } ''
            install -D -m 0755 ${pkgs.fetchurl {
              url = "https://github.com/open-policy-agent/opa/releases/download/v1.20.1/${opaTarget.asset}";
              inherit (opaTarget) hash;
            }} "$out/bin/opa"
          '';
          tofuTarget =
            {
              aarch64-darwin = {
                asset = "darwin_arm64";
                hash = "sha256-4IPuQ3kKueGa1m2ZM+JKckShQS4dVyjzeZmuIWP9rJU=";
              };
              x86_64-linux = {
                asset = "linux_amd64";
                hash = "sha256-XcQ9pPdQ8zhz3CXpRYcShwnoGeVEt76QFrJVMWFTw6g=";
              };
            }
            .${system};
          tofu = pkgs.runCommand "opentofu-1.12.6" { nativeBuildInputs = [ pkgs.unzip ]; } ''
            archive=${pkgs.fetchurl {
              url = "https://github.com/opentofu/opentofu/releases/download/v1.12.6/tofu_1.12.6_${tofuTarget.asset}.zip";
              inherit (tofuTarget) hash;
            }}
            mkdir -p "$TMPDIR/unpack"
            unzip -q "$archive" -d "$TMPDIR/unpack"
            install -D -m 0755 "$TMPDIR/unpack/tofu" "$out/bin/tofu"
          '';
          toolchainPackages = with pkgs; [
            actionlint
            bash
            bazelisk
            buildifier
            cacert
            coreutils
            curl
            findutils
            gh
            git
            gnugrep
            gnused
            gnutar
            go_1_26
            gzip
            jq
            just
            nixfmt-rfc-style
            opa
            python314
            shellcheck
            tofu
            unzip
            yamllint
            yq-go
          ];
          toolchain = pkgs.buildEnv {
            name = "mindclade-github-config-toolchain";
            paths = toolchainPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
            ignoreCollisions = false;
          };
        in
        {
          inherit toolchain;
          default = toolchain;
        }
      );

      devShells = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          common = {
            packages = [ toolchain ];
            LANG = "C.UTF-8";
            LC_ALL = "C.UTF-8";
            TZ = "UTC";
            USE_BAZEL_VERSION = "9.2.0";
          };
        in
        {
          default = pkgs.mkShell common;
          ci = pkgs.mkShell (common // { CI = "true"; });
        }
      );

      formatter = forAllSystems (_: pkgs: pkgs.nixfmt-rfc-style);

      checks = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          githubConfigCtl = pkgs.buildGoModule {
            pname = "github-configctl";
            version = "1.0.0";
            src = "${self}/compiler";
            vendorHash = pkgs.lib.fakeHash;
            subPackages = [ "cmd/github-configctl" ];
          };
        in
        {
          toolchain = pkgs.runCommand "mindclade-github-config-toolchain-check" {
            nativeBuildInputs = [ toolchain ];
          } ''
            set -euo pipefail
            test "$(actionlint -version)" = "1.7.12"
            test "$(go version | awk '{print $3}')" = "go1.26.7"
            test "$(just --version)" = "just 1.58.0"
            test "$(opa version --format json | jq -r .version)" = "1.20.1"
            test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.14.7"
            test "$(tofu version -json | jq -r .terraform_version)" = "1.12.6"
            test "${pkgs.bazelisk.version}" = "1.29.0"
            grep -Fq '>=9.2.0' ${self}/MODULE.bazel
            grep -Fq '<=9.2.0' ${self}/MODULE.bazel
            grep -Fq 'go_sdk.download(version = "1.26.7")' ${self}/MODULE.bazel
            grep -Fq 'go 1.26.7' ${self}/compiler/go.mod
            mkdir -p "$out"
            printf '%s\n' '${nixpkgs.rev}' > "$out/nixpkgs-revision"
          '';

          source = pkgs.runCommand "mindclade-github-config-source-check" {
            nativeBuildInputs = [
              githubConfigCtl
              toolchain
            ];
          } ''
            set -euo pipefail
            mkdir -p "$out"
            github-configctl --root ${self} validate > "$out/validation.json"
            opa test ${self}/policy > "$out/policy.txt"
          '';
        }
      );
    };
}
