"""Authenticate Dash's private binary cache without putting secrets in Nix."""

import argparse
import base64
import getpass
import json
import multiprocessing
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path


@dataclass(frozen=True)
class Cache:
    endpoint: str
    name: str
    public_key: str

    @property
    def url(self) -> str:
        return f"{self.endpoint}/{self.name}"


def load_cache() -> Cache:
    settings = json.loads(Path(os.environ["DASH_CACHE_SETTINGS"]).read_text())
    key = settings.get("public_key")
    if not isinstance(key, str) or not re.fullmatch(r"[\w-]+:[A-Za-z0-9+/]{43}=", key):
        raise ValueError(
            "Cache signing key is unpublished; an operator must run cache-admin.sh init."
        )
    if len(base64.b64decode(key.split(":", 1)[1], validate=True)) != 32:
        raise ValueError("Invalid cache signing key.")
    name = settings["cache"]
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid cache name.")
    endpoint = os.environ.get(
        "DASH_CACHE_ENDPOINT",
        settings.get("endpoint") or f"https://{settings['app']}.fly.dev",
    ).rstrip("/")
    parsed = urllib.parse.urlsplit(endpoint)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme != "https" and not (local and parsed.scheme == "http")
    ) or not parsed.hostname:
        raise ValueError(
            "Cache endpoint must use HTTPS (HTTP is allowed only on loopback for tests)."
        )
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path
    ):
        raise ValueError(
            "Cache endpoint must be an origin without credentials, path, or query."
        )
    return Cache(endpoint, name, key)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


METADATA_MAX_BYTES = 131_072
METADATA_TIMEOUT_SECONDS = 30


def _verify_metadata(cache: Cache, token: str) -> None:
    request = urllib.request.Request(
        f"{cache.endpoint}/_api/v1/cache-config/{cache.name}",
        headers={"Authorization": f"Bearer {token}"},
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=METADATA_TIMEOUT_SECONDS) as response:
            raw = response.read(METADATA_MAX_BYTES + 1)
        if len(raw) > METADATA_MAX_BYTES:
            raise ValueError("Cache metadata exceeds the 128 KiB response limit.")
        try:
            metadata = json.loads(raw)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise ValueError("Cache metadata is not a valid JSON object.") from error
    except urllib.error.HTTPError as error:
        raise ValueError(
            f"Cache authentication failed (HTTP {error.code}); request a current read token."
        ) from error
    except urllib.error.URLError as error:
        raise ValueError(
            "Cache is unreachable; check the endpoint and Fly service status."
        ) from error
    if not isinstance(metadata, dict) or metadata.get("is_public") is not False:
        raise ValueError("Expected a private cache; refusing to configure this server.")
    if metadata.get("public_key") != cache.public_key:
        raise ValueError(
            "Cache signing key differs from the published key; ask an operator to investigate."
        )
    if metadata.get("substituter_endpoint", "").rstrip("/") != cache.url:
        raise ValueError("Server advertised an unexpected binary cache endpoint.")


def _metadata_worker(
    cache: Cache, token: str, result: Connection, deadline: float
) -> None:
    """Own one bounded request; return only a small credential-free verdict."""
    try:
        # A real-time OS alarm also closes sockets and inherited output pipes
        # if the parent is killed. Its default action cannot be delayed by a
        # Python exception handler or a blocked DNS/TLS/socket operation.
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Cache metadata request timed out.")
        signal.setitimer(signal.ITIMER_REAL, remaining)
        _verify_metadata(cache, token)
        answer = (True, "")
    except ValueError as error:
        answer = (False, str(error))
    except Exception:  # noqa: BLE001 -- this process boundary must redact unexpected failures
        # Worker failures must not print provider bodies or credential-bearing
        # exception details through multiprocessing's default traceback handler.
        answer = (False, "Cache metadata request failed.")
    try:
        result.send(answer)
    except (OSError, EOFError):
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        result.close()


def verify(cache: Cache, token: str) -> None:
    # urllib's timeout resets for each socket operation. A separate owned worker
    # bounds DNS, TLS, headers, slow response reads and parsing together without
    # relying on private socket attributes. Credentials travel in a private IPC
    # pipe, never process arguments or environment variables.
    context = multiprocessing.get_context("spawn")
    result, delivery = context.Pipe(duplex=False)
    deadline = time.monotonic() + METADATA_TIMEOUT_SECONDS
    worker = context.Process(
        target=_metadata_worker, args=(cache, token, delivery, deadline)
    )
    worker.daemon = True
    cancellation_signals = (signal.SIGTERM, signal.SIGINT)
    previous_handlers = {
        signum: signal.getsignal(signum) for signum in cancellation_signals
    }
    starting = True
    cleaning = False
    interrupted = None

    def cancel(signum, _frame):
        nonlocal cleaning, interrupted
        interrupted = signum
        # Defer cancellation while acquiring the child handle or reaping it;
        # repeated signals must neither interrupt cleanup nor be discarded.
        if not starting and not cleaning:
            cleaning = True
            raise SystemExit(128 + signum)

    try:
        for signum in cancellation_signals:
            signal.signal(signum, cancel)
        worker.start()
        # Do not unwind Process.start midway through acquiring its child handle.
        starting = False
        if interrupted is not None:
            raise SystemExit(128 + interrupted)
        delivery.close()
        remaining = max(0, deadline - time.monotonic())
        if not result.poll(remaining):
            raise ValueError("Cache metadata request timed out.")
        try:
            accepted, message = result.recv()
        except (OSError, EOFError) as error:
            if time.monotonic() >= deadline:
                raise ValueError("Cache metadata request timed out.") from error
            raise ValueError("Cache metadata request failed.") from error
        if not accepted:
            raise ValueError(message)
    finally:
        cleaning = True
        try:
            delivery.close()
            result.close()
            if worker.pid is not None:
                if worker.is_alive():
                    worker.terminate()
                worker.join(timeout=1)
                if worker.is_alive():
                    worker.kill()
                    worker.join(timeout=1)
                worker.close()
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
    if interrupted is not None:
        raise SystemExit(128 + interrupted)


def write_private(destination: Path, text: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=destination.parent, delete=False
    ) as staged:
        staged.write(text)
        staged_path = Path(staged.name)
    try:
        staged_path.chmod(0o600)
        staged_path.replace(destination)
    finally:
        staged_path.unlink(missing_ok=True)


def include_config(destination: Path, fragment: Path) -> None:
    current = destination.read_text() if destination.exists() else ""
    line = f"!include {fragment}"
    if line not in current.splitlines():
        write_private(
            destination,
            current
            + ("\n" if current and not current.endswith("\n") else "")
            + line
            + "\n",
        )


def run(command: list[str], **kwargs) -> None:
    subprocess.run(command, check=True, **kwargs)


def restart_nix_daemon(sudo: list[str]) -> None:
    """Restart the single loaded Nix service."""
    if sys.platform != "darwin":
        run(sudo + ["systemctl", "restart", "nix-daemon.service"])
        return

    services = (
        "system/org.nixos.nix-daemon",
        "system/systems.determinate.nix-daemon",
    )
    loaded = [
        service
        for service in services
        if subprocess.run(
            sudo + ["launchctl", "print", service],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    ]
    if len(loaded) != 1:
        raise ValueError(
            "Expected exactly one loaded Nix daemon; inspect launchctl before retrying."
        )
    run(sudo + ["launchctl", "kickstart", "-k", loaded[0]])


def setup(cache: Cache, root: Path, args: argparse.Namespace) -> None:
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()
    else:
        token = getpass.getpass("Personal read-only Attic token: ").strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError(
            "Provide one nonempty cache token via prompt, stdin, or --token-file."
        )
    verify(cache, token)
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    user_conf = config_home / "nix/nix.conf"
    system_conf = Path("/etc/nix/nix.conf")
    if args.user_only:
        if user_conf.is_symlink():
            raise ValueError(
                "User nix.conf is managed; import the cache module in the owning flake."
            )
    elif not args.credentials_only:
        # The installer reserves nix.custom.conf for user additions.
        if (
            system_conf.exists()
            and "include nix.custom.conf" in system_conf.read_text()
        ):
            system_conf = Path("/etc/nix/nix.custom.conf")
        if system_conf.is_symlink():
            raise ValueError(
                "System nix.conf is managed; import nixosModules.cache or darwinModules.cache, then use setup --credentials-only."
            )

    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    write_private(root / "token", token + "\n")
    host = urllib.parse.urlsplit(cache.endpoint).hostname
    write_private(root / "netrc", f"machine {host} login token password {token}\n")
    # An isolated Attic config preserves any personal servers. token-file keeps
    # credentials out of process arguments, shell history and the Nix store.
    write_private(
        root / "attic/config.toml",
        (
            f"[servers.dash]\nendpoint = {json.dumps(cache.endpoint + '/')}\n"
            f"token-file = {json.dumps(str(root / 'token'))}\n"
        ),
    )
    netrc = str(root / "netrc") if args.user_only else "/etc/nix/dash-cache.netrc"
    fragment = (
        f"extra-substituters = {cache.url}\n"
        f"extra-trusted-public-keys = {cache.public_key}\n"
        f"netrc-file = {netrc}\n"
    )
    write_private(root / "nix.conf", fragment)
    if args.user_only:
        include_config(user_conf, root / "nix.conf")
        print(
            "Private cache configured for this user. Multi-user Nix requires daemon trust; use the standard setup on developer laptops."
        )
    else:
        sudo = [] if os.geteuid() == 0 else ["sudo"]
        run(
            sudo
            + ["install", "-m", "600", str(root / "netrc"), "/etc/nix/dash-cache.netrc"]
        )
        if not args.credentials_only:
            # Back up once; never replace the host's existing settings.
            run(
                sudo
                + [
                    "install",
                    "-m",
                    "644",
                    str(root / "nix.conf"),
                    "/etc/nix/dash-cache.conf",
                ]
            )
            line = "!include /etc/nix/dash-cache.conf"
            existing = system_conf.read_text() if system_conf.exists() else ""
            if line not in existing.splitlines():
                if system_conf.exists():
                    run(
                        sudo
                        + [
                            "cp",
                            "-n",
                            str(system_conf),
                            str(system_conf) + ".before-dash-cache",
                        ]
                    )
                run(
                    sudo + ["tee", "-a", str(system_conf)],
                    input=f"\n{line}\n",
                    text=True,
                    stdout=subprocess.DEVNULL,
                )
            restart_nix_daemon(sudo)
        print(
            "Private cache credentials installed for the Nix daemon. Run dash-cache status to verify access."
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup_parser = commands.add_parser(
        "setup", help="configure authenticated downloads; prompts for a token"
    )
    setup_parser.add_argument("--token-file")
    modes = setup_parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--user-only",
        action="store_true",
        help="CI/single-user Nix; daemon must already trust the cache",
    )
    modes.add_argument(
        "--credentials-only",
        action="store_true",
        help="install daemon credentials for a declaratively configured machine",
    )
    status_parser = commands.add_parser(
        "status", help="verify credentials and published cache identity"
    )
    status_parser.add_argument("--offline", action="store_true")
    push_parser = commands.add_parser(
        "push", help="upload explicit store paths and their closures; CI token required"
    )
    push_parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    cache = load_cache()
    root = (
        Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
        / "dash-dev-env/cache"
    )
    if args.command == "setup":
        setup(cache, root, args)
    else:
        if not (root / "token").exists():
            raise ValueError(
                "Cache credentials missing; run dash-setup cache (or dash-cache setup)."
            )
        if args.command == "status":
            if not args.offline:
                verify(cache, (root / "token").read_text().strip())
            print(
                f"Private cache: {cache.url} ({'credentials installed; access unchecked' if args.offline else 'authenticated'})"
            )
        elif args.command == "push":
            if any(
                not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[^/\s]+", p)
                for p in args.paths
            ):
                raise ValueError(
                    "push accepts /nix/store paths; build first with nix build --print-out-paths."
                )
            run(
                ["attic", "push", f"dash:{cache.name}", *args.paths],
                env=dict(os.environ, XDG_CONFIG_HOME=str(root)),
            )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"dash-cache: {error}", file=sys.stderr)
        sys.exit(1)
