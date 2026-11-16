"""M1 - trusted identities for an AgentDojo environment.

A real deployment would read these from the user's organisation directory and
account settings. In AgentDojo we derive them from the environment *before* the
agent starts, using only sources an outside attacker cannot write to:

  workspace  the user's own address; addresses on the user's organisation
             domain (the company directory); people the user has sent e-mail to.
  slack      members of the user's own Slack workspace.
  banking,   none (payment recipients and bookings are never treated as
  travel     trusted identities).

Deliberately NOT used: AgentDojo's inbox contact list, which is built from every
sender of a received e-mail, so anyone who e-mails the user (including a
phisher) would become trusted. Calendar participants are not used either,
because anyone can send a meeting invitation.
"""
from __future__ import annotations


def trusted_identities(env) -> set[str]:
    ids: set[str] = set()
    inbox = getattr(env, "inbox", None)
    if inbox is not None:
        own = str(inbox.account_email).lower()
        ids.add(own)
        domain = own.split("@")[-1]
        addresses = {str(c.email).lower() for c in getattr(inbox, "contact_list", [])}
        for e in inbox.emails.values():
            addresses |= {str(x).lower() for x in [e.sender, *e.recipients, *e.cc, *e.bcc]}
            if str(e.sender).lower() == own:          # people the user wrote to
                ids |= {str(x).lower() for x in [*e.recipients, *e.cc, *e.bcc]}
        ids |= {a for a in addresses if a.endswith("@" + domain)}   # organisation directory
    slack = getattr(env, "slack", None)
    if slack is not None:
        ids |= {str(u).lower() for u in slack.users}
    return ids
