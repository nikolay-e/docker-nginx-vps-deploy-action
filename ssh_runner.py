import logging
import os
import socket
import tempfile
from io import StringIO
from typing import Optional

from fabric import Connection, Result
from invoke import UnexpectedExit
from paramiko.ssh_exception import AuthenticationException, SSHException

# Local imports
from utils import decode_if_base64 # Assuming utils.py is in the same directory

log = logging.getLogger(__name__)

class SSHRunner:
    """Handles SSH connection, key management, and command execution."""

    def __init__(self, host: str, user: str, ssh_key_secret: Optional[str], connect_timeout: int = 30):
        self.host = host
        self.user = user
        self._ssh_key_secret = ssh_key_secret
        self._connect_timeout = connect_timeout
        self.connection: Optional[Connection] = None
        self.temp_key_path: Optional[str] = None

        self._setup_key()
        self._connect()

    def _setup_key(self):
        """Prepares the temporary SSH key file."""
        log.debug("Setting up SSH key file...")
        if not self._ssh_key_secret:
            raise ValueError("SSH private key secret is missing or empty.")

        ssh_key_decoded = decode_if_base64(self._ssh_key_secret)
        if not ssh_key_decoded:
            raise ValueError("SSH key content is empty after potential decoding.")
        if "-----BEGIN" not in ssh_key_decoded:
            log.warning("SSH Key content does not look like PEM. Authentication might fail.")

        # Slightly modified write_temp_key_file from utils for internal use
        try:
            fd, self.temp_key_path = tempfile.mkstemp(prefix="runner_ssh_key_")
            log.debug(f"Writing SSH key to temporary file: {self.temp_key_path}")
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(ssh_key_decoded)
                if not ssh_key_decoded.endswith('\n'):
                    f.write('\n')
            os.chmod(self.temp_key_path, 0o600)
        except (OSError, IOError) as e:
            self.close() # Attempt cleanup if key writing fails
            log.critical(f"Failed to write temporary SSH key file: {e}")
            raise IOError("Failed to write temporary SSH key file") from e

    def _connect(self):
        """Establishes the SSH connection."""
        if not self.temp_key_path:
            raise RuntimeError("SSH key file not prepared before connecting.")

        log.info(f"Attempting SSH connection to {self.user}@{self.host}...")
        connect_kwargs = {"key_filename": self.temp_key_path}

        try:
            self.connection = Connection(
                host=self.host,
                user=self.user,
                connect_timeout=self._connect_timeout,
                connect_kwargs=connect_kwargs
            )
            # Test connection by running a simple command
            self.connection.run("echo 'SSH connection successful'", hide=True)
            log.success("SSH connection established successfully.")
        except (AuthenticationException, SSHException, socket.gaierror, TimeoutError, OSError, UnexpectedExit) as e:
            log.critical(f"SSH connection failed: {e.__class__.__name__}: {e}")
            # Provide hints based on exception type
            error_message = "Check VPS host/IP, username, SSH service status, network, firewall."
            if isinstance(e, AuthenticationException):
                error_message += " Verify SSH key and authorized_keys on VPS."
            if isinstance(e, socket.gaierror):
                 error_message += " Could not resolve hostname."
            log.critical(error_message)
            self.close() # Ensure cleanup on connection error
            raise RuntimeError("SSH connection failed") from e
        except Exception as e:
            log.critical(f"Unexpected error during SSH connection: {e}", exc_info=True)
            self.close()
            raise RuntimeError("Unexpected SSH connection error") from e

    def run(self, command: str, **kwargs) -> Result:
        """Runs a command using connection.run with enhanced logging/error handling."""
        return self._run_remote_cmd(command, sudo=False, **kwargs)

    def sudo(self, command: str, **kwargs) -> Result:
        """Runs a command using connection.sudo with enhanced logging/error handling."""
        return self._run_remote_cmd(command, sudo=True, **kwargs)

    def put(self, local_file_obj, remote_path):
         """Uploads a file-like object."""
         if not self.connection: raise RuntimeError("SSH connection lost")
         try:
              log.debug(f"Uploading file object to {remote_path}")
              return self.connection.put(local_file_obj, remote_path)
         except (IOError, OSError, SSHException) as e:
              log.error(f"Failed to upload file object to {remote_path}: {e}")
              raise IOError(f"Failed to upload file object to {remote_path}") from e

    def _run_remote_cmd(self, command: str, sudo: bool = False, hide: bool = True, warn: bool = False, pty: bool = False, capture: bool = False, error_msg_prefix: str = "Command failed") -> Optional[Result]:
        """Internal helper to run commands, handle exceptions and logging."""
        if not self.connection or not self.connection.is_connected:
             log.critical("SSH connection lost or not established.")
             raise RuntimeError("SSH connection lost")

        runner = self.connection.sudo if sudo else self.connection.run
        action = "sudo" if sudo else "run"
        log.debug(f"Executing ({action}): {command}")

        try:
            result = runner(command, hide=hide, warn=True, pty=pty) # Use warn=True always

            if result.ok:
                log.debug(f"Command successful (exit code {result.exited}): {command}")
                if not hide or log.isEnabledFor(logging.DEBUG):
                     if result.stdout: log.debug(f"STDOUT:\n{result.stdout.strip()}")
                     if result.stderr: log.debug(f"STDERR:\n{result.stderr.strip()}")
                return result if capture else None # Return Result only if capture=True
            else:
                # Command failed
                log_func = log.warning if warn else log.error
                log_func(f"{error_msg_prefix}: '{command}' exited with code {result.exited}.")
                # Always log output on failure
                if result.stdout: log_func(f"Failed command STDOUT:\n{result.stdout.strip()}")
                if result.stderr: log_func(f"Failed command STDERR:\n{result.stderr.strip()}")

                # Add hints
                stderr_lower = result.stderr.lower()
                if "command not found" in stderr_lower: log_func("Hint: Ensure command is installed and in PATH.")
                elif "permission denied" in stderr_lower: log_func(f"Hint: Check permissions for '{self.user}' or required sudo.")
                elif "no such file" in stderr_lower: log_func("Hint: Check file/directory path.")

                if not warn:
                    raise RuntimeError(f"{error_msg_prefix}: Command exited with code {result.exited}")
                return None # Return None on failure if warn=True

        except Exception as e: # Catch other unexpected errors
            log_func = log.warning if warn else log.critical
            log_func(f"Exception executing command: {command}", exc_info=True)
            if not warn:
                raise RuntimeError(f"Exception during command execution") from e
            return None


    def close(self):
        """Closes SSH connection and removes temporary key file."""
        log.debug("Closing SSHRunner resources...")
        if self.connection and self.connection.is_connected:
            self.connection.close()
            log.debug("SSH connection closed.")
        if self.temp_key_path and os.path.exists(self.temp_key_path):
            log.debug(f"Removing temporary SSH key file: {self.temp_key_path}")
            try:
                os.remove(self.temp_key_path)
            except OSError as e:
                log.warning(f"Could not remove temp key file {self.temp_key_path}: {e}")
        self.temp_key_path = None
        self.connection = None