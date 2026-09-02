{
  description = "Pinned system toolchain for github.com/mindclade/github-config";

  nixConfig = {
    substituters = [ "https://cache.nixos.org/" ];
    trusted-public-keys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
    require-sigs = true;
  };

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c";

  outputs =
    { self, nixpkgs }:
    let
      policy = import ./generated/nix-bazel-policy.nix;
      manifestDefaults = builtins.fromJSON (
        builtins.readFile ./generated/toolchain-manifest.defaults.json
      );
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
    assert policy.generated.authority_repository == "mindclade/.github";
    assert policy.generated.authority_revision == "49a015c2c0cdd6a75a5756eb8c1e95b49d117917";
    assert manifestDefaults.authority.revision == policy.generated.authority_revision;
    assert nixpkgs.rev == policy.spec.nixpkgs.revision;
    assert nixpkgs.narHash == policy.spec.nixpkgs.nar_hash;
    assert builtins.all (system: builtins.elem system policy.spec.systems) systems;
    {
      packages = forAllSystems (
        system: pkgs:
        let
          biomePolicy = policy.spec.tools.biome;
          biomeTarget = biomePolicy.targets.${system};
          biome = pkgs.runCommand "biome-${biomePolicy.version}" { } ''
            install -D -m 0755 ${
              pkgs.fetchurl {
                url = "https://github.com/biomejs/biome/releases/download/%40biomejs/biome%40${biomePolicy.version}/${biomeTarget.asset}";
                inherit (biomeTarget) hash;
              }
            } "$out/bin/biome"
          '';
          opaPolicy = policy.spec.tools.opa;
          opaTarget = opaPolicy.targets.${system};
          opa = pkgs.runCommand "opa-${opaPolicy.version}" { } ''
            install -D -m 0755 ${
              pkgs.fetchurl {
                url = "https://github.com/open-policy-agent/opa/releases/download/v${opaPolicy.version}/${opaTarget.asset}";
                inherit (opaTarget) hash;
              }
            } "$out/bin/opa"
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
            archive=${
              pkgs.fetchurl {
                url = "https://github.com/opentofu/opentofu/releases/download/v1.12.6/tofu_1.12.6_${tofuTarget.asset}.zip";
                inherit (tofuTarget) hash;
              }
            }
            mkdir -p "$TMPDIR/unpack"
            unzip -q "$archive" -d "$TMPDIR/unpack"
            install -D -m 0755 "$TMPDIR/unpack/tofu" "$out/bin/tofu"
          '';
          bazelRuntimeInputs =
            with pkgs;
            [
              bash
              bazel_9
              bzip2
              cacert
              coreutils
              curl
              diffutils
              file
              findutils
              gawk
              git
              gnugrep
              gnumake
              gnused
              gnutar
              gzip
              jdk21_headless
              jq
              openssl.bin
              openssh
              patch
              stdenv.cc
              unzip
              which
              xz
              zip
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [
              darwin.cctools
              darwin.cctools.libtool
            ];
          bazel = pkgs.writeShellApplication {
            name = "bazel";
            runtimeInputs = bazelRuntimeInputs;
            text = ''
              export PATH=${pkgs.lib.makeBinPath bazelRuntimeInputs}
              export JAVA_HOME=${pkgs.jdk21_headless}
              export CC=${pkgs.stdenv.cc}/bin/cc
              export CXX=${pkgs.stdenv.cc}/bin/c++
              export BAZEL_LINKOPTS=${pkgs.lib.escapeShellArg (pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "-L${pkgs.darwin.libresolv}/lib")}
              export LANG=C
              export LC_ALL=C
              export TZ=UTC
              if [[ "''${1:-}" == "--version" ]]; then
                printf 'bazel %s\n' '${policy.spec.bazel.version}'
                exit 0
              fi
              startup_flags=(--nosystem_rc --nohome_rc --server_javabase=${pkgs.jdk21_headless})
              if [[ -n "''${BAZEL_OUTPUT_USER_ROOT:-}" ]]; then
                startup_flags+=(--output_user_root="''${BAZEL_OUTPUT_USER_ROOT}")
              fi
              exec ${pkgs.bazel_9}/bin/bazel "''${startup_flags[@]}" "$@"
            '';
          };
          moduleLock = "${self}/MODULE.bazel.lock";
          toolchainManifest = pkgs.writeTextDir "share/mindclade/toolchain-manifest.json" (
            builtins.toJSON {
              schema_version = "mindclade-toolchain.v1";
              repository = "mindclade/github-config";
              policy_authority = manifestDefaults.authority;
              inherit system;
              nixpkgs = {
                revision = nixpkgs.rev;
                nar_hash = nixpkgs.narHash;
              };
              flake_lock_sha256 = builtins.hashFile "sha256" "${self}/flake.lock";
              module_lock_sha256 =
                if builtins.pathExists moduleLock then builtins.hashFile "sha256" moduleLock else null;
              bazel = {
                version = manifestDefaults.bazel.version;
                store_path = "${pkgs.bazel_9}";
              };
              startup_jdk = {
                major = manifestDefaults.bazel.startup_jdk_major;
                version = pkgs.jdk21_headless.version;
                store_path = "${pkgs.jdk21_headless}";
              };
              native_cc_store_path = "${pkgs.stdenv.cc}";
            }
          );
          toolchainPackages =
            with pkgs;
            [
              actionlint
              bash
              bazel
              biome
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
              golangci-lint
              gzip
              jq
              just
              jdk21_headless
              markdownlint-cli2
              nixfmt
              opa
              pre-commit

              pyright

              python314

              ruff
              shellcheck
              shfmt
              stdenv.cc
              tofu
              toolchainManifest
              unzip
              yamllint
              yq-go
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.libresolv ];
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
          "toolchain-manifest" = toolchainManifest;
          default = toolchain;
        }
      );

      devShells = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          darwinDeploymentTarget = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "14.0";
          locale = if pkgs.stdenv.hostPlatform.isDarwin then "en_US.UTF-8" else "C.UTF-8";
          common = {
            packages = [ toolchain ];
            MACOSX_DEPLOYMENT_TARGET = darwinDeploymentTarget;
            JAVA_HOME = "${pkgs.jdk21_headless}";
            CC = "${pkgs.stdenv.cc}/bin/cc";
            CXX = "${pkgs.stdenv.cc}/bin/c++";
            LANG = locale;
            LC_ALL = locale;
            TZ = "UTC";
          };
        in
        {
          default = pkgs.mkShell common;
          ci = pkgs.mkShell (common // { CI = "true"; });
        }
      );

      formatter = forAllSystems (_: pkgs: pkgs.nixfmt);

      checks = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          githubConfigCtl = pkgs.buildGoModule {
            pname = "github-configctl";
            version = "1.0.0";
            src = "${self}/compiler";
            vendorHash = "sha256-UVaaiY1gDpx3/Le2N7Qmf2WzH8MCM5MtlxuMKKaZtM0=";
            subPackages = [ "cmd/github-configctl" ];
          };
        in
        {
          toolchain =
            pkgs.runCommand "mindclade-github-config-toolchain-check"
              {
                nativeBuildInputs = [ toolchain ];
              }
              ''
                set -euo pipefail
                test "$(biome --version)" = "Version: ${policy.spec.tools.biome.version}"
                test "${pkgs.buildifier.version}" = "8.5.1"
                test "${pkgs.golangci-lint.version}" = "2.13.1"
                test "${pkgs.markdownlint-cli2.version}" = "0.23.2"
                test "$(pre-commit --version)" = "pre-commit 4.5.1"
                test "$(pyright --version)" = "pyright 1.1.412"
                test "$(ruff --version)" = "ruff 0.16.4"
                test "$(shfmt --version)" = "3.13.1"
                test "$(actionlint -version | head -n1)" = "1.7.12"
                test "$(go version | awk '{print $3}')" = "go1.26.7"
                test "$(just --version)" = "just 1.58.0"
                test "$(opa version | awk '/^Version:/ {print $2}')" = "${policy.spec.tools.opa.version}"
                test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.14.7"
                test "$(tofu version -json | jq -r .terraform_version)" = "1.12.6"
                test "$(bazel --version)" = "bazel ${policy.spec.bazel.version}"
                grep -Fq '>=9.1.1' ${self}/MODULE.bazel
                grep -Fq '<=9.1.1' ${self}/MODULE.bazel
                grep -Fq 'go_sdk.download(version = "1.26.7")' ${self}/MODULE.bazel
                grep -Fq 'go 1.26.7' ${self}/compiler/go.mod
                jq -e '.schema_version == "mindclade-toolchain.v1" and .bazel.version == "9.1.1" and .policy_authority.revision == "49a015c2c0cdd6a75a5756eb8c1e95b49d117917"' \
                  ${toolchain}/share/mindclade/toolchain-manifest.json >/dev/null
                mkdir -p "$out"
                printf '%s\n' '${nixpkgs.rev}' > "$out/nixpkgs-revision"
              '';

          source =
            pkgs.runCommand "mindclade-github-config-source-check"
              {
                nativeBuildInputs = [
                  githubConfigCtl
                  toolchain
                ];
              }
              ''
                set -euo pipefail
                mkdir -p "$out"
                github-configctl --root ${self} validate > "$out/validation.json"
                opa test ${self}/policy > "$out/policy.txt"
              '';
        }
      );
    };
}
