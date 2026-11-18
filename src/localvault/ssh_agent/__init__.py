"""SSH agent (Windows): vault SSH keys on a per-user named pipe, every signature approved by the user."""
from .server import SshAgentServer, default_pipe_name
from .service import SshAgentService

__all__ = ["SshAgentServer", "SshAgentService", "default_pipe_name"]
