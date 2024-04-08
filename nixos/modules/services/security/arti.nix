{ config, lib, options, pkgs, ... }:

with builtins;
with lib;

let
  cfg = config.services.arti;
  opt = options.services.arti;
  stateDir = "/var/lib/arti"; # XXX
  runDir = "/run/arti"; # XXX
  descriptionGeneric = option: ''
    An implementation of Tor, in Rust.
  '';
  settingsFormat = pkgs.formats.toml { };
  defaultConfig = { };
  filterConfig = converge (filterAttrsRecursive (n: _: n != "enable" && n != "package"));
  artiConfig = settingsFormat.generate "config.toml" (defaultConfig // (filterConfig cfg));
in
{
  options = {
    services.arti = {
      enable = mkEnableOption "Arti daemon. TODO";

      # TODO: do we need this??
      package = mkPackageOption pkgs "arti" { };

      logging = {
        log_sensitive_information = mkEnableOption ''
          Whether to log sensitive information (such as target hostnames and ip addresses)

          If set to `false` (the default), such information is not logged in messages of
          level `info` or higher.
        '';
      };

      onion_services = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            proxy_ports = mkOption {
              type = types.listOf (types.listOf types.str); # XXX
              default = [ ];
              description = ''
                A description of what to do with incoming connections to different ports.
                This is given as a list of rules; the first matching rule applies.
              '';
            };
          };
        });
        default = { };
        description = ''
          NOTE: Some of the security features needed for onion service privacy
          are not yet implemented.  See
          <https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/OnionService.md>
          for more information.

          Configuration for an onion service.  You can include multiple
          `[onion_services]` sections in order to configure multiple onion services.

          The second part of this section's name ("allum-cepa") is a local nickname
          for this onion service.

          This nickname is saved on disk, and used to tell onion services apart;
          it is not visible outside your own Arti instance.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    users.groups.arti.gid = config.ids.gids.arti;
    users.users.arti = {
      description = "Arti Daemon User";
      createHome = false;
      home = stateDir;
      group = "arti";
      uid = config.ids.uids.arti;
    };

    systemd.services.arti = {
      description = "Arti Daemon";
      path = [ pkgs.arti ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      restartTriggers = [ artiConfig ]; #XXX
      serviceConfig = {
        Type = "simple";
        User = "arti";
        Group = "arti";
        ExecStart = "${cfg.package}/bin/arti proxy -c ${artiConfig}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        KillSignal = "SIGINT";
        Restart = "on-failure";
        LimitNOFILE = 32768;
        StateDirectoryMode = "0700";
        StateDirectory = [
          "arti"
        ];
        BindPaths = [ stateDir ];
        BindReadOnlyPaths = [ storeDir "/etc" ] ++
          optionals config.services.resolved.enable [
            "/run/systemd/resolve/stub-resolv.conf"
            "/run/systemd/resolve/resolv.conf"
          ];
        DeviceAllow = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateMounts = true;
        PrivateNetwork = mkDefault false;
        PrivateTmp = true;
        ProcSubset = "all"; # must be set to "all" because arti reads from /proc/self/status
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        # See also the finer but experimental option settings.Sandbox
        SystemCallFilter = [
          "@system-service"
        ];
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";
      };
    };
    environment.systemPackages = [ cfg.package ];
  };
}
