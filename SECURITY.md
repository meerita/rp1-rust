# Security Policy

## Supported versions

RP-1 Rust is in early development and has no published release. Report a
vulnerability against the current state of the `master` branch.

## Reporting a vulnerability

Send a report to **meerita@icloud.com**.

Do not open a public issue for a vulnerability. Do not disclose the
problem publicly before a fix exists.

Include what you can:

- A description of the problem and what it lets an attacker do.
- The affected revision.
- The Rust version and the platform.
- Steps to reproduce, or a test case.
- Any input that triggers the problem, such as a byte sequence a server
  can send.
- A suggested fix, if you have one.

## What to expect

You get an acknowledgement of the report. You get an assessment of
whether the problem is confirmed, and of what it affects. You get told
when a fix lands.

A confirmed problem is fixed before it is described publicly. The report
credits you unless you ask otherwise.

## Scope

The client parses input that a server controls. Anything that lets that
input cause memory unsafety, a panic reachable through the public API,
unbounded memory use, or an unbounded loop is in scope.

A problem in the RP-1 server is not in scope here. Report it through the
RP-1 server project.
