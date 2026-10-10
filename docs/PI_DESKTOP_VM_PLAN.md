# Pi Desktop on Minions VM — Architecture Plan

## Status

Planning document only. No implementation is implied by this document.

---

## Goal

Build a client application that feels like a local Pi experience, while the actual Pi runtime, tools, workspace, and sessions live on a remote machine.

The client may be either:

- a **desktop app**, or
- a **browser app using xterm.js**

In this model:

- the **client is the UI**
- the **remote machine is the source of truth**
- **Pi runs remotely**
- **tmux keeps the Pi process alive across disconnects**
- an infrastructure layer such as **Minions may optionally manage lifecycle, snapshots, exposure, and cloning**

This gives us a portable, resumable, isolated coding environment with a strong client UX.

---

## Why this direction

The original idea was to let a local Pi act as a proxy to a remote machine. After exploring Pi's architecture and Minions' capabilities, a stronger model emerged:

- Pi already works well as a full terminal application
- Minions already gives us stateful VMs, SSH access, snapshots, HTTPS exposure, and cloning
- tmux already solves session persistence and reconnectability
- a desktop app can package the terminal experience without requiring the agent to run locally

Instead of splitting the agent across local and remote machines, we keep the agent whole and remote.

That means:

- code lives remotely
- tools run remotely
- sessions live remotely
- the desktop app is mainly a transport + UX layer

This makes the VM the canonical environment and avoids weird split-brain behavior.

---

## High-level architecture

### Base architecture: browser-first, no central backend

```text
┌──────────────────────────────────────┐
│ Browser App                          │
│                                      │
│ - xterm.js                           │
│ - workspace selector                 │
│ - reconnect logic                    │
│ - optional preview UI                │
└────────────────┬─────────────────────┘
                 │
                 │ HTTPS / WebSocket
                 │
┌────────────────▼─────────────────────┐
│ Remote Machine                       │
│                                      │
│ - web terminal gateway (e.g. ttyd)   │
│ - tmux                               │
│ - Pi installed                       │
│ - workspace repo(s)                  │
│ - toolchain: git, rg, fd, node, etc. │
│ - Pi sessions/config                 │
│                                      │
│ tmux session runs:                   │
│   cd /workspace && pi                │
└──────────────────────────────────────┘
```

### Optional provider layer: Minions-backed version

```text
┌──────────────────────────────────────┐
│ Client App                           │
│                                      │
│ - browser or desktop UI              │
│ - terminal surface                   │
│ - VM/workspace controls              │
└────────────────┬─────────────────────┘
                 │
                 │ SSH / HTTPS / Minions API
                 │
┌────────────────▼─────────────────────┐
│ Minions Host / Platform              │
│                                      │
│ - VM lifecycle API                   │
│ - SSH gateway                        │
│ - HTTPS reverse proxy                │
│ - snapshot / backup / clone          │
└────────────────┬─────────────────────┘
                 │
                 │ attach to VM
                 │
┌────────────────▼─────────────────────┐
│ Minions VM                           │
│                                      │
│ - Pi installed                       │
│ - tmux session                       │
│ - workspace repo(s)                  │
│ - toolchain: git, rg, fd, node, etc. │
│ - Pi sessions/config                 │
│                                      │
│ tmux session runs:                   │
│   cd /workspace && pi                │
└──────────────────────────────────────┘
```

---

## Core principle

### The VM is the source of truth

Everything important should live inside the VM:

- source code
- git checkout
- installed dependencies
- language runtimes
- dev servers
- Pi session files
- Pi config/auth if we choose
- shell state and background processes

The desktop app should not try to maintain an alternate authoritative state.

Its job is to:

- connect
- render
- manage lifecycle
- improve usability

---

## Recommended product shape

## V1: terminal-based remote Pi client

The simplest and strongest first version is:

- package Pi's existing TUI experience as-is
- do **not** rewrite Pi's UI yet
- use a terminal surface as the client UI
- connect that terminal to a remote tmux session hosting Pi

There are two valid client forms:

### A. Browser-first client using xterm.js

- browser renders terminal via xterm.js
- remote machine runs a web terminal gateway such as `ttyd`
- gateway attaches to `tmux`
- `tmux` hosts a persistent `pi` process

### B. Desktop app with embedded terminal

- desktop app embeds a terminal
- desktop app SSHes into the remote machine
- desktop app attaches to `tmux`
- `tmux` hosts a persistent `pi` process

### Current preferred V1

Given the current constraints:

- xterm.js is already in use
- no central backend is desired
- plain SSH access may be the only guaranteed infrastructure

The preferred V1 is:

- **browser-first**
- **no central backend**
- **per-host web terminal gateway**
- **tmux-hosted Pi on the remote machine**

From the user's perspective, this still feels like a Pi app. Operationally, it is a remote terminal attached to a persistent remote Pi runtime.

### Why V1 should be terminal-based

Because it minimizes risk:

- no need to build a custom Pi client protocol immediately
- no need to reimplement Pi's TUI behavior
- Pi works exactly as it does today
- tmux already gives persistence
- reconnects are easy
- debugging is straightforward
- the system can always be inspected over plain SSH
- a browser client can be shipped quickly if xterm.js is already part of the stack

This is the fastest route to a usable product.

---

## Why tmux is important

tmux is not just convenient; it is foundational for this design.

### What tmux gives us

- **process persistence**: Pi survives network drops and app restarts
- **resume**: reconnect later and continue exactly where you left off
- **debuggability**: engineers can SSH in and inspect the exact running session
- **multiple clients**: more than one viewer can attach if needed
- **background jobs**: dev servers, tailing logs, helper shells, etc.
- **shell continuity**: the environment around Pi can persist with it

### What runs in tmux

The baseline plan is one named session per workspace/VM, for example:

- session name: `pi`
- command: `cd /workspace && pi`

A thin launcher script in the VM is preferable so startup logic stays centralized.

Example intent:

```bash
tmux new-session -A -s pi 'cd /workspace && pi'
```

The desktop app should treat tmux as the session anchor.

---

## Why not keep Pi local and proxy tools remotely

We explored that design too.

It has one attractive property:

- API keys can stay on the local machine

But it adds complexity and splits the system awkwardly:

- Pi state is local, but workspace is remote
- session files must be synced in both directions
- background processes and shell state are remote, but context logic is local
- snapshots must coordinate local session state with remote disk state
- failures can create mismatch between local and remote truth

By contrast, remote Pi + tmux keeps the model coherent:

- one machine owns the agent
- one machine owns the workspace
- one machine owns the session files
- one machine is snapshotted

That is much easier to reason about.

---

## Desktop app responsibilities

The desktop app should add value around Pi, not replace Pi immediately.

### Core responsibilities

- authenticate user to Minions platform
- list available workspaces/VMs
- create/start/stop/delete VMs
- snapshot and restore VMs
- connect terminal to the remote Pi tmux session
- reconnect automatically if transport drops
- display VM status
- open exposed preview URLs
- show lightweight metadata like cost, region, status, age

### Nice-to-have responsibilities

- embedded browser for app previews
- command palette for VM actions
- recent workspaces list
- notifications when VM boots or reconnects
- settings for region, machine size, auto-sleep, etc.
- activity history for snapshots and restores

### What the desktop app should not own in V1

- Pi message/session logic
- tool execution logic
- conversation persistence
- workspace filesystem state
- shell orchestration inside the VM beyond launching/attaching tmux

---

## Transport options

There are three meaningful approaches.

## Option A — Browser-first via per-host web terminal gateway

This is the current preferred V1.

### Model

- browser app embeds xterm.js
- remote machine runs a web terminal gateway such as `ttyd`
- browser connects directly to that gateway over HTTPS / WebSocket
- gateway attaches to the tmux session
- tmux runs Pi

### Benefits

- no central backend required
- browser can connect directly to the remote machine
- fits naturally if xterm.js is already in use
- Pi runs unchanged
- tmux persistence still works
- simplest path to a usable browser product

### Downsides

- there is still a server-side bridge, but it lives on each remote host
- auth/security must be handled per host or via reverse proxy
- lifecycle, snapshots, and previews are not centralized unless a provider like Minions is added later

---

## Option B — Desktop app with embedded terminal over SSH

This remains a strong alternative V1.

### Model

- app embeds a terminal emulator
- app opens SSH to the remote machine or Minions SSH gateway
- remote command attaches to the tmux session
- terminal bytes are rendered directly in the app

### Benefits

- simple architecture
- leverages existing OpenSSH and tmux behavior
- Pi runs unchanged
- works even if Pi evolves internally
- easy to debug with normal terminal tools

### Downsides

- app is effectively a polished terminal wrapper
- richer structured UI is harder at first
- desktop-native affordances need extra integration

---

## Option C — Custom UI over Pi RPC / bridge

This is the likely V2 direction.

### Model

- Pi runs remotely in RPC mode or behind an RPC bridge
- client speaks a structured protocol
- app renders chat panes, tools, messages, previews, etc. natively

### Benefits

- much richer UI possibilities
- better control over layout and interactions
- easier to fuse workspace controls with chat state elegantly

### Downsides

- much more engineering
- requires a robust bridge/protocol layer
- higher maintenance
- would likely require custom handling for reconnects and persistence

### Recommendation

Do not start here.

Build V1 as a terminal-based remote Pi client first, then evolve toward RPC if product demand justifies it.

---

## Provider model: plain SSH first, Minions optionally later

The core architecture should not depend on Minions.

A good abstraction is:

- **remote workspace = host + working directory + tmux session + Pi installation**

Under that abstraction, the product works even if all we know is:

- there is a remote machine
- we can SSH into it
- we have keys

That is enough for a functional V1 if the remote machine also runs a web terminal gateway such as `ttyd`.

### Plain SSH / generic host mode

In the minimal mode, the app only assumes:

- HTTPS access to the remote terminal gateway
- SSH access for setup/debugging if needed
- `tmux` installed remotely
- `pi` installed remotely
- a known workspace directory, e.g. `/workspace`

This mode is enough to validate the product experience.

### Minions-backed mode

Minions then becomes an optional infrastructure/provider layer that adds:

- on-demand VM creation
- start / stop / restart
- snapshots and restore
- VM cloning / copy-on-write
- SSH gateway
- HTTPS proxy / exposed previews
- multi-host placement if needed later
- API surface for orchestration

### Why this abstraction is useful

It lets the product start with plain SSH and evolve into Minions later without changing the core client model.

The frontend still thinks in terms of:

- connect to workspace
- render terminal
- reconnect to tmux-hosted Pi

Only the provisioning and lifecycle layer changes.

---

## VM image requirements

For the experience to feel good, the VM image should come with Pi and common dev tools preinstalled.

## Baseline image contents

### Pi runtime

- `pi` installed and on `PATH`
- any required auth/config bootstrap path decided
- a launcher script for tmux entry

### Shell/session tools

- `tmux`
- `bash`
- `git`
- `curl`
- `jq`

### Search and navigation

- `ripgrep`
- `fd`
- `tree`

### Language/runtime basics

- Node.js / bun if needed
- Python if needed
- common build tooling

### Workspace convention

- standard working directory, e.g. `/workspace`
- optional per-project subdirs later

### Optional extras

- Docker if nested/container workflows matter
- language-specific tools depending on target user base

### Important requirement

The image should be opinionated enough that a new VM is useful immediately.

If a new VM needs 10 minutes of setup before Pi can work, the UX falls apart.

---

## Pi placement and state

Because Pi runs in the VM, we need to decide what lives there.

## Recommended initial stance

Store Pi state in the VM too.

That includes:

- Pi session files
- Pi settings
- Pi auth if acceptable
- extensions/skills if needed

### Why

This keeps the experience coherent:

- restore a VM snapshot → restore the Pi session state too
- clone a VM → clone the environment and agent context too
- reconnect from another machine → same Pi state

### Caveat

This means secrets may live in the VM.

That is acceptable if:

- VMs are considered trusted per-user environments
- VM access is properly protected
- snapshot and backup handling is treated accordingly

If storing LLM credentials in the VM is not acceptable, we need a more complex split design. That should be treated as a separate security architecture decision, not the default.

---

## Session persistence model

The persistence stack should be:

1. **Pi session files** inside the VM
2. **Pi process** kept alive by tmux
3. **VM disk** persisted by Minions
4. **Snapshots** used as explicit checkpoints

This gives multiple layers of durability:

- app closes: tmux keeps Pi alive
- network drops: tmux keeps Pi alive
- host reboot or VM stop/start: Pi session files still exist
- risky refactor: restore snapshot

---

## Reconnect model

Reconnect should be a first-class feature, not an accident.

## Desired user behavior

A user should be able to:

- close the app
- reopen it later
- reconnect to the same workspace
- land in the same Pi session in tmux

## Desired failure behavior

If connectivity drops:

- app shows reconnecting state
- tmux session continues remotely
- app reattaches automatically when possible

The user should not lose the agent session merely because the client disconnected.

---

## Preview model

One of the strongest product combinations here is:

- Pi builds an app inside the VM
- app runs a dev server or web server in the VM
- Minions exposes that port
- desktop app surfaces the preview link or embeds it

### Example workflow

1. user asks Pi to create a web app
2. Pi starts server on port `3000`
3. desktop app calls Minions expose action
4. preview opens at `https://vmname.domain.com`
5. app can show preview beside the terminal in a split view

This is a major UX win and should be in scope early.

---

## Snapshots as product feature

Snapshots are not just infrastructure; they are a core UX primitive for AI-assisted coding.

### Why snapshots matter here

Before a risky action, the user or app can checkpoint the full environment:

- code
- installed dependencies
- background processes state on disk
- Pi session files
- shell environment persisted in files

### Product opportunities

- “Create checkpoint” button
- auto-snapshot before destructive operations
- timeline of named snapshots
- restore and continue from earlier state
- duplicate workspace from snapshot

This is more powerful than just git for many workflows.

---

## VM cloning as product feature

Minions copy/clone support maps naturally to agent workflows.

### Example uses

- fork a workspace before a large experiment
- create a staging clone from a dev environment
- branch an investigation without disturbing the main VM

This could become a first-class UI action later:

- Duplicate workspace
- Open clone in new app window

---

## Security considerations

This architecture is simple, but it shifts trust to the VM.

## Questions to answer explicitly

### 1. Where do LLM credentials live?

Options:

- inside the VM
- proxied from a backend
- delegated from local machine

Recommended for initial simplicity:

- store them in the VM for user-owned/stateful workspaces

### 2. How is SSH authenticated?

Possible options:

- user SSH keys
- app-managed keypair
- ephemeral session keys issued by platform

For a desktop product, app-managed or platform-issued credentials will likely feel better than requiring users to hand-configure SSH.

### 3. How are snapshots protected?

If snapshots contain Pi sessions and credentials, backup/restore paths need the right security posture.

### 4. Is direct shell access allowed?

Probably yes for power users and debugging. That is a feature, not a bug, but the product should acknowledge it.

---

## Why a desktop app is still valuable if it is “just a terminal”

Because it is not really just a terminal.

The app can package a complete workflow:

- workspace selection
- stateful connection management
- lifecycle controls
- snapshot controls
- preview browser
- usage/cost visibility
- reconnect UX
- onboarding

The embedded terminal is only the rendering surface for Pi itself.

That is enough for a very compelling V1.

---

## Product phases

## Phase 0 — Manual proof of concept

Validate the core interaction manually on a generic remote host:

- install Pi, tmux, and a web terminal gateway such as `ttyd`
- create a remote workspace directory
- run `tmux new -A -s pi 'cd /workspace && pi'`
- expose that session through the gateway
- connect from the browser
- disconnect and reconnect
- verify the same Pi session is still there

If Minions is available, also test snapshots / restore and preview exposure, but that is optional for proving the core model.

Success criteria:

- the workflow feels good enough to want a productized client

---

## Phase 1 — Browser app with embedded terminal

Build the first real product version.

### Features

- xterm.js terminal client
- connect to a configured remote workspace
- direct browser connection to per-host terminal gateway
- auto-attach to remote Pi tmux session
- reconnect after disconnect
- basic workspace metadata / status UI

### Non-goals

- custom message renderer for Pi
- replacing Pi UI
- central backend for session bridging
- multi-VM orchestration in one workspace
- local/offline mode

Success criteria:

- a user can do real work in the browser without opening a separate terminal

---

## Phase 2 — Provider integration and UX refinement

Improve product quality without changing the core architecture.

### Features

- split panes: terminal + preview
- workspace metadata panel
- better onboarding and first-run provisioning
- polished reconnect flows
- optional Minions integration for:
  - snapshot history UI
  - VM metadata panel
  - auto-sleep / wake behavior
  - template workspaces / base images

---

## Phase 3 — Structured remote protocol exploration

Only after V1/V2 validate demand.

### Exploration targets

- Pi RPC bridge in VM
- native desktop rendering of conversations/tool calls
- hybrid mode: structured UI plus fallback terminal attachment
- desktop-first workflows beyond terminal emulation

This phase should be earned, not assumed.

---

## Technical recommendation summary

## Recommended V1

Build a browser app that:

1. uses xterm.js as the terminal surface
2. connects directly to a per-host web terminal gateway such as `ttyd`
3. lands in a named tmux session on the remote machine
4. launches Pi inside that tmux session if not already running
5. treats the remote machine as the source of truth
6. avoids a central backend terminal bridge

## Why this is the right starting point

- lowest complexity under the current constraints
- fits an xterm.js-based frontend naturally
- keeps the remote machine as source of truth
- avoids building custom SSH/RPC bridging infrastructure too early
- easy to debug and operate
- easy to evolve later into Minions-backed provisioning and lifecycle management

---

## Open design questions

These should be answered before implementation starts.

### Product / UX

- Should each workspace map to exactly one VM?
- Should the app support multiple simultaneous VM windows?
- Should preview be embedded or external browser first?
- Should snapshot creation be manual only, or also automatic before risky actions?

### Platform

- Do we ship a custom VM image with Pi preinstalled?
- Do we allow user-customized images?
- Do we want app-managed SSH credentials?
- Do we need a lightweight bootstrap service inside the VM beyond tmux + Pi?

### Security

- Are LLM credentials allowed to reside in the VM?
- How do backups/snapshots handle secrets?
- What does account recovery/device change look like?

### Future architecture

- When would we move from terminal rendering to RPC-based native UI?
- Do we want both modes long term?

---

## Proposed next step

Do **not** start by building a complex Pi protocol bridge.

Start with a narrow proof of concept:

1. prepare a remote host with Pi + tmux + a web terminal gateway such as `ttyd`
2. validate remote Pi usability through tmux manually
3. connect to it from a browser using xterm.js
4. verify reconnect behavior and session continuity
5. only after that, decide whether Minions should be layered in for provisioning, snapshots, and previews

If that works well, the architecture is validated.

If users later want deeper client-native interactions, we can build a structured bridge on top of a system that already works.

---

## One-sentence conclusion

The best first implementation is a **browser app using xterm.js that connects directly to a per-host web terminal gateway attached to a tmux-hosted Pi instance on a remote machine**, with Minions treated as an optional later provider for lifecycle, snapshot, and preview primitives.
