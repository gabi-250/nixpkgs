{ config, lib, options, pkgs, ... }:

with builtins;
with lib;

let
  cfg = config.services.arti;
  stateDir = "/var/lib/arti"; # XXX
  descriptionGeneric = option: ''
    An implementation of Tor, in Rust.
  '';
  settingsFormat = pkgs.formats.toml { };
  defaultConfig = { };
  filterConfig = converge (filterAttrsRecursive (n: v: n != "enable" && n != "package" && v != null));
  artiConfig = settingsFormat.generate "config.toml" (defaultConfig // (filterConfig cfg));
in
{
  options = {
    services.arti = {
      enable = mkEnableOption "Arti daemon. TODO";
      package = mkPackageOption pkgs "arti" { };
      application = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            watch_configuration = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                If true, we should watch our configuration files for changes.

                (Note that this feature may misbehave if you change symlinks in the
                paths to the directory holding the configuration files, if you
                remove and recreate those directories, or if those directories
                change for some other reason.)
              '';
            };
            permit_debugging = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                If true, we should allow other processes run by the same user to inspect this
                process's memory.

                (By default, assuming arti has been built with the `harden` feature flag, we
                take what step we can, including disabling core dumps, to keep its memory and
                state secret from other processes.)
              '';
            };
            allow_running_as_root = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                If true, then we allow Arti to start even if the current user is root.

                (By default, we exit if we are running as root, since this is usually a
                mistake.)
              '';
            };
          };
        });
        default = null;
        description = ''
          Rules about how arti should behave as an application
        '';
    };

      proxy = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            socks_listen = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = ''
                Default port to use when listening to SOCKS connections.  We always
                listen on localhost.

                Note that only one process can listen on a given port at a time.
              '';
            };
            dns_listen = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = ''
                Port to use to listen for DNS requests.  0 means disabled.
              '';
            };
          };
        });
        default = null;
        description = ''
          Set up the Arti program to run as a proxy.
        '';
      };

      logging = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            console = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Specify filtering directives for sending trace messages to the console
                (via standard output).

                It can be as simple as a single loglevel, or as complicated as a
                list with per-module settings.

                You can override this setting with the -l, --log-level command-line option.

                Example:
                    trace_filter = "info,tor_proto::channel=trace"

                For more information, see https://docs.rs/tracing-subscriber/0.2.20/tracing_subscriber/filter/struct.EnvFilter.html
              '';
            };
            journald = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                As above, but specify filtering directives for sending trace messages to
                the journald logging system.  Empty string means not to use journald.
              '';
            };
            files = mkOption {
              type = types.listOf (types.submodule {
                options = {
                  path = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      Where to write the files?
                    '';
                  };
                  filter = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      Filter to apply before writing
                    '';
                  };
                  rotate = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      How often to rotate the file?
                    '';
                  };
                };
              });
              default = [];
              description = ''
                 You can also configure one or more log files, with different filters, and optional
                 rotation.

                 For example (not the default): XXX write in nix
                files = [
                         {path = "~/logs/debug.log", filter="debug"},
                         {path = "~/logs/trace.log", filter="trace", rotate="daily"},
                ]
              '';
            };
            log_sensitive_information = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                Whether to log sensitive information (such as target hostnames and ip addresses)

                If set to `false` (the default), such information is not logged in messages of
                level `info` or higher.
              '';
            };
            time_granularity = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                The granularity with which to display times in our logs.

                When logging persistently, it can be risky to record very precise timing
                information: if the logs are later exposed or compromised, they can help
                traffic analysis attacks.

                To lower this risk, we support rounding the times in our logs, and displaying
                them with less precision.  This option configures the maximum degree of
                precision we'll use.  (We may use even a little less precision if you specify
                an odd interval of time.)

                This option can't affect the granularity of times recorded by logging systems
                outside of arti, including journald.
              '';
            };
          };
        });
        default = null;
        description = ''
          Configure logging
        '';
      };

      storage = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            cache_dir = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                TODO
              '';
            };
            state_dir = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                TODO
              '';
            };
            keystore = mkOption {
              type = types.nullOr (types.submodule {
                options = {
                  enabled = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      Whether the keystore is enabled.

                      If the `keymgr` feature is enabled and this option is:
                          * set to false, we will ignore the configured keystore path.
                          * set to "auto", the configured keystore, or the default keystore, if the
                          keystore path is not specified, will be used
                          * set to true, the configured keystore, or the default keystore, if the
                          keystore path is not specified, will be used

                      If the `keymgr` feature is disabled and this option is:
                          * set to false, we will ignore the configured keystore path.
                          * set to "auto", we will ignore the configured keystore path.

                      Setting this option to true when the `keymgr` feature is disabled is a
                      configuration error.
                    '';
                  };
                };
              });
              default = null;
              description = '' TODO '';
            };

            permissions = mkOption {
              type = types.nullOr (types.submodule {
                options = {
                  dangerously_trust_everyone = mkOption {
                    type = types.nullOr types.bool;
                    default = null;
                    description = ''
                      If set to true, we ignore all filesystem permissions.
                    '';
                  };
                  trust_user = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      What user (if any) is trusted to own files and directories?  ":current" means
                      to trust the current user.
                    '';
                  };
                  trust_group = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      What group (if any) is trusted to have read/write access to files and
                      directories?  ":selfnamed" means to trust the group with the same name as the
                      current user, if that user is a member.
                    '';
                  };
                  ignore_prefix = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                    description = ''
                      If set, gives a path prefix that will always be trusted.  For example, if this
                      option is set to "/home/", and we are checking "/home/username/.cache", then
                      we always accept the permissions on "/" and "/home", but we check the
                      permissions on "/home/username" and "/home/username/.cache".

                      (This is not the default.)
                    '';
                  };
                };
              });
              default = null;
              description = '' TODO '';
            };
          };
        });
      default = null;
      description = ''TODO '';
    };

    bridges = mkOption {
      type = types.nullOr (types.submodule {
        options = {
          enable = mkOption {
            type = types.nullOr (types.oneOf [ types.str types.bool ]);
            default = null;
            description = ''
              Should we use configured bridges?
                  If set to false, we will ignore the configured bridges.
                  If set to "auto", we will use any bridges that are configured.
                  If set to true, bridges must be configured and will be used.
            '';
          };
          bridges = mkOption {
            type = types.nullOr (types.listOf types.str);
            default = null;
            description = ''
              What bridges (including pluggable transports) to use, in this syntax:
               bridges = [
                   "<IP>:<ORPort> <fingerprint> [<fingerprint> ...]",
                   "<transport> <host>:<ORPort>|- <fingerprint> [...] [<key>=<val> ...]",
               ]

              For example:
               bridges = [
                   "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                   "[2001:db8::3150]:8080 $0bac39417268b96b9f514e7f63fa6fb1aa788957",
                   "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
               ]

              You may specify all the bridge lines in one multi-line string:
               bridges = '''
               192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956
               [2001:db8::3150]:8080 $0bac39417268b96b9f514e7f63fa6fb1aa788957
               obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1
               '''

              (Note that these are just examples, not real bridges - they will not work.)
          '';
          };

          transports = mkOption {
            type = types.nullOr (types.listOf (types.submodule {
              options = {
                protocols = mkOption {
                  type = types.listOf (types.str);
                  default = [ ];
                  description = ''
                    Which pluggable transports does this binary provide?
                  '';
                };
                path = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = ''
                    Path to the binary to be run.
                  '';
                };
                arguments = mkOption {
                  type = types.listOf (types.str);
                  default = [ ];
                  description = ''
                    Any command-line arguments to pass to the binary (empty if not specified).
                  '';
                };
                run_on_startup = mkOption {
                  type = types.nullOr types.bool;
                  default = null;
                  description = ''
                    Should we run this binary on startup? If false or unspecified, the binary will be
                    launched when we first attempt to use any of the transports it provides instead.
                  '';
                };
                proxy_addr = mkOption {
                  type = types.nullOr types.str;
                  default = null;
                  description = ''
                    Where can we contact this transport?
                    (This should be a local SOCKS5 proxy address.)
                  '';
                };
              };
            }));
            default = null;
            description = ''
              An example managed pluggable transport binary.
                 [[bridges.transports]]

              Which pluggable transports does this binary provide?
                 protocols = ["obfs4", "obfs5"]

              Path to the binary to be run.
                 path = "/usr/bin/obfsproxy"

              Any command-line arguments to pass to the binary (empty if not specified).
                 arguments = ["-obfs4", "-obfs5"]

              Should we run this binary on startup? If false or unspecified, the binary will be
              launched when we first attempt to use any of the transports it provides instead.
                 run_on_startup = true

              An example unmanaged pluggable transport.
                 [[bridges.transports]]

              Which protocols does this transport provide?
                 protocols = ["obfs4"]

              Where can we contact this transport?
              (This should be a local SOCKS5 proxy address.)
                 proxy_addr = "127.0.0.1:31337"
            '';
          };
        };
      });
      default = null;
      description = ''
        Bridges (for anticensorship support)
      '';
    };

    # TODO override_net_params
    # TODO download_schedule

      directory_tolerance = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            pre_valid_tolerance = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                For how long before a directory document is valid should we accept it?
              '';
            };
            post_valid_tolerance = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                For how long after a directory document is valid should we consider it usable?
              '';
            };
          };
        });
        default = null;
        description = ''
          Information about how premature or expired our directories are allowed to be.

          These options help us tolerate clock skew, and help survive the case where the
          directory authorities are unable to reach consensus for a while.
        '';
      };

      path_rules = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            ipv4_subnet_family_prefix = mkOption {
              type = types.nullOr types.ints.unsigned; # XXX u8
              default = null;
              description = ''
                Set the length of a bit-prefix for a default IPv4 subnet-family.

                Any two relays will be considered to belong to the same family if their
                IPv4 addresses share at least this many initial bits.
              '';
            };
            ipv6_subnet_family_prefix = mkOption {
              type = types.nullOr types.ints.unsigned; # XXX u8
              default = null;
              description = ''
                Set the length of a bit-prefix for a default IPv6 subnet-family.

                Any two relays will be considered to belong to the same family if their
                IPv6 addresses share at least this many initial bits.
              '';
            };
          };
        });
        default = null;
        description = ''
          Tells the circuit manager rule for constructing circuit paths
        '';
      };

      preemptive_circuits = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            disable_at_threshold = mkOption {
              type = types.nullOr types.ints.unsigned;
              default = null;
              description = ''
                If we have at least this many available circuits, we suspend
                construction of preemptive circuits. whether our available circuits
                support our predicted exit ports or not.
              '';
            };
            initial_predicted_ports = mkOption {
              type = types.nullOr (types.listOf types.ints.unsigned); # XXX [u16]
              default = null;
              description = ''
                At startup, which exit ports should we expect that the client will want?

                (Over time, new ports are added to the predicted list, in response to
                what the client has actually requested.)

                This value cannot be changed on a running Arti client, because doing so
                would be meaningless.
              '';
            };
            prediction_lifetime = mkOption {
              type = types.nullOr types.str; # XXX duration humantime_serde
              default = null;
              description = ''
                After we see the client request a connection to a new port, how long
                should we predict that the client will still want to have circuits
                available for that port?
              '';
            };
            min_exit_circs_for_port = mkOption {
              type = types.nullOr types.ints.unsigned; # XXX
              default = null;
              description = ''
                How many available circuits should we try to have, at minimum, for each
                predicted exit port?
              '';
            };
          };
        });
        default = null;
        description = ''
          Configure preemptive circuit construction.

          Preemptive circuits are built ahead of time, to anticipate client need. This
          section configures the way in which this demand is anticipated and in which
          these circuits are constructed.
        '';
      };

      # TODO tor_network

      channel = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            padding = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Should we use reduced channel padding?  (This roughly halves the padding
                cell frequency, and makes the padding unidirectional, increasing the
                traceability of the client connections.)
                Or disable it entirely?

                Can be "normal", "reduced", or "none".
              '';
            };
          };
        });
        default = null;
        description = ''
          Channels and their behaviour
        '';
      };

      # Full manual control of the precise padding timing parameters is available
      # by setting `override_net_params.nf_ito_low` et al.
      # (See torpsec/padding-spec.txt section 3.4.)

      circuit_timing = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            max_dirtiness = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                Once a circuit has been used for a request, we stop giving it out for
                other requests after this time.
              '';
            };
            request_timeout = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                When a circuit is requested, we keep trying to build circuits for up
                to this long before the request gives up.
              '';
            };
            request_max_retries = mkOption {
              type = types.nullOr types.ints.unsigned;
              default = null;
              description = ''
                When a circuit is requested, we make up to this many attempts to build
                circuits for it before the request gives up.
              '';
            };
            request_loyalty = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                If a circuit is finished that would satisfy a pending request, but the
                request is still waiting for its own circuits to complete, the request
                will wait this long before using the unexpectedly available circuit.
              '';
            };
            hs_desc_fetch_attempts = mkOption {
              type = types.nullOr types.ints.unsigned;
              default = null;
              description = ''
                When we're trying to connect to a hidden service (.onion service),
                how many attempts  will we make to download the descriptor from the directories.
              '';
            };
            hs_intro_rend_attempts = mkOption {
              type = types.nullOr types.ints.unsigned;
              default = null;
              description = ''
                When we're trying to connect to a hidden service (.onion service),
                how many attempts  will we make to
                conduct the introduction and rendezvous exchange, before giving up.
              '';
            };
          };
        });
        default = null;
        description = ''
          Rules for how long circuits should survive, and how long pending
          requests should wait for a circuit.
        '';
      };

      address_filter = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            allow_local_addrs = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                Should we allow attempts to make Tor connections to local addresses?
              '';
            };
            allow_onion_addrs = mkOption {
              type = types.nullOr types.bool;
              default = null;
              description = ''
                Should Arti make connections to hidden services (.onion services) ?

                As of this implementation, Arti's onion service support lacks the
                "vanguards" feature that Tor uses to prevent guard discovery attacks over time.
                As such, you should probably stick with C Tor if you need to make a large
                number of onion service connections, or if you are using the Tor protocol
                in a way that lets an attacker control how many onion services connections that you make -
                for example, when using Arti's SOCKS support from a web browser such as Tor Browser.

                Therefore, the onion service client support  is currently disabled by default.
              '';
            };
          };
        });
        default = null;
        description = ''
          Rules for which addresses a client is willing to try to connect to over
          the tor network.
        '';
      };

      stream_timeouts = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            connect_timeout = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                How long should we wait before timing out a stream when connecting to a host?
              '';
            };
            resolve_timeout = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                How long should we wait before timing out when resolving a DNS record?
              '';
            };
            resolve_ptr_timeout = mkOption {
              type = types.nullOr types.str;
              default = null;
              description = ''
                How long should we wait before timing out when resolving a DNS PTR record?
              '';
            };
          };
        });
        default = null;
        description = ''
          Rules for how long streams should wait when connecting to host or performing a
          DNS lookup.

          These timeouts measure the permitted time between sending a request on an
          established circuit, and getting a response from the exit node.
        '';
      };

      system = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            max_files = mkOption {
              type = types.nullOr types.ints.unsigned;
              default = null;
              description = ''
                What is the maximum number of file descriptors which should be available
                to Arti when we launch?
              '';
            };
          };
        });
        default = null;
        description = ''
          Configuration for the system resources used by Arti.
        '';
      };

      onion_services = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            proxy_ports = mkOption {
              type = types.nullOr (types.listOf (types.listOf types.str)); # XXX
              default = null;
              description = ''
                A description of what to do with incoming connections to different ports.
                This is given as a list of rules; the first matching rule applies.
              '';
            };
            anonimity = mkOption {
              type = types.nullOr (types.oneOf [ types.bool types.str ]);
              default = null;
              description = ''
                Whether to run an _anonymous_ onion service, or non-anonymous service
                (also called a "single onion service"). Anonymity is the default.
                In order to run a non-anonymous service, set this value to the
                string "not_anonymous".
              '';
            };
            num_intro_points = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = ''
                Number of introduction points to establish and advertise.
              '';
            };
            max_concurrent_streams_per_circuit = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = ''
                How many streams will we allow at a time for each circuit?
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
      restartTriggers = [ artiConfig ];
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
        StateDirectory = [ "arti" ];
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
        # Must be set to "all" because arti reads from /proc/self/status
        ProcSubset = "all";
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
