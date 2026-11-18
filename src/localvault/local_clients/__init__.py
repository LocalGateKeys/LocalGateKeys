"""Who is calling and may it have this secret: the shared approval layer for local clients.

The SSH agent and the ``lgk`` CLI identify the calling process (:mod:`.identity`) and ask the user before a
secret leaves the vault (:mod:`.approvals`).
"""
from .approvals import ApprovalRequest, Approvals, default_approvals
from .identity import ClientIdentity, identify

__all__ = ["ApprovalRequest", "Approvals", "ClientIdentity", "default_approvals", "identify"]
