# How I built Samba Key with Qwen, Pi and pi-here

[Español](DESARROLLO.md)

This is the story of how Samba Key was made, written for two kinds of reader: people who are curious about working with a **local** coding model, and people who want to repeat the setup. It also tells, without varnish, what went wrong along the way. You do **not** need any of these tools to install or use Samba Key.

## Why the project exists

Samba Key started at home. We share folders on a Samba server, and when someone forgets their password, changing it falls to whoever administers the server. I wanted everyone to be able to change their own password easily, and to ask for help when they had forgotten the old one. Plenty of other families, groups of friends and small teams must have the same need, so the goal became a small, reusable tool rather than something only for my house. [The README](../README.md) describes the problem in more detail.

It was also an excuse to try something else: a coding workflow built around a model running on my own machine.

## The toolchain at a glance

| Piece | What it is | Why I used it |
|---|---|---|
| [Pi](https://pi.dev) | A light, extensible coding agent for the terminal. | A "blank slate" I could build on, instead of a heavier environment. |
| [Ollama](https://ollama.com) | A program that downloads and serves language models locally. | It runs the model on my computer; no code leaves the machine. |
| **Qwen 3.8 27B** | The model that did most of the work. Recorded in the session logs as `ollama/qwen3.8:27b`; the name is whatever my installation reported, so check what your Ollama calls it. | A capable local model, used with *medium* reasoning effort. |
| [pi-here](https://github.com/fedeblock/pi-here) | A launcher I wrote that starts Pi in a folder with a chosen model, reasoning level, extensions and skills. | See the next section. |
| Extensions and skills | Permission checks, protected paths, [Superpowers](https://www.npmjs.com/package/@tsubus/pi-superpowers) and skills for planning, test-driven development, debugging and verification. | Guardrails and good habits for a model that is smaller than the hosted ones. |
| An advisor | A tool that lets the working model ask a second, stronger model for an opinion. I used **Anthropic's Sonnet 5.5** through its API. | A second pair of eyes on design and security questions. |

Using a local model has real trade-offs. **In its favour:** the code and the conversation stay on my machine, there is no per-token bill, and it works offline. **Against:** it is slower and less capable than the large hosted models, a long context costs real time, and the whole experiment depends on a fairly powerful computer. The advisor was an escape hatch for the hardest questions; it is an optional paid API and *does* send the conversation to a third party, so I configured its key separately and kept it out of the repository.

## Setting up Pi with pi-here

### Why a launcher

Every tool, extension and skill that Pi loads adds text to the system prompt. With a local model, more prompt means slower processing, and changing the set invalidates the model's cache. So the decision about *what to load* belongs at launch, and it differs by job: a quick fix, a long build session, a read-only review. `pi-here` makes that choice visible. You run it in a project folder, it shows you the exact command it is about to run, and you press Enter.

### Installing it, on macOS or Linux

`pi-here` supports macOS and Linux; Windows is untested. Its own [README](https://github.com/fedeblock/pi-here#install) is the reference for current requirements.

1. **Install Ollama** from [ollama.com](https://ollama.com) and pull a model your hardware can run. Check the model's size on its Ollama page before downloading; a 27B model needs a lot of memory.
2. **Install Pi** by following the instructions at [pi.dev](https://pi.dev).
3. **Install Node.js** 20.12 or newer, then install pi-here from a clone:

   ```sh
   git clone https://github.com/fedeblock/pi-here.git
   cd pi-here
   npm install
   npm link            # puts `pi-here` on your PATH
   pi-here --version   # check
   ```

4. **Install the extensions or skills you want**, with Pi itself, for example `pi install npm:@tsubus/pi-superpowers`. *Read a package's code first: extensions run with your user's permissions.*
5. In your project folder, run `pi-here config` to choose what each preset loads, then `pi-here --dry-run` to see the command it will run.

### A profile

This is an illustration of the *shape* of a pi-here profile (`~/.config/pi-here/config.json`), not Samba Key configuration. The paths are placeholders for extensions and skills you have installed and reviewed yourself:

```json
{
  "launcher": "ollama",
  "presets": {
    "samba-example": {
      "model": "qwen3.8:27b",
      "thinking": "medium",
      "extensions": {"mode": "only", "load": ["/path/to/reviewed-extension.ts"]},
      "skills": {"mode": "only", "load": ["/path/to/reviewed-skill/SKILL.md"]}
    }
  }
}
```

With a profile like this, `pi-here --dry-run` prints something shaped like:

```
ollama launch pi --model qwen3.8:27b -- --thinking medium --no-extensions --extension /path/to/reviewed-extension.ts --no-skills ...
```

Two things worth saying plainly. First, a profile makes launching convenient; it is **not a security boundary**, so permission extensions and protected paths are managed separately. Second, the model name above is the one my installation used; yours may differ.

## How the work went

I decided priorities, read the proposals and chose what to do next. Qwen did much of the implementation and documentation, and the skills I loaded nudged it towards small steps: write a test, make it pass, run everything. When I wanted a different perspective on a design or security question, I asked Sonnet. Over six days (11 to 16 November) the work took 64 commits, in roughly this order:

1. **A password-change page** in English and Spanish that calls Samba's own client and needs no administrative access to the server.
2. **Hardening that flow**, including a fix so that the *current* password is not forced to satisfy the *new*-password length rule.
3. **Forgotten-password recovery**, which went through a redesign: first a portal that handled more than it should, then a separate privileged *authority* that owns the contact channels and the delivery.
4. **Proof against a real Samba**: disposable containers for the password change, the reset, privilege separation and the full chain.
5. **Trials on a real host** with a dedicated test account, real email and a real Telegram bot.
6. **Documentation**, repeatedly, as the code stopped agreeing with it.

Two files in the repository exist because of this way of working: [AGENTS.md](../AGENTS.md) (the rules any coding agent must follow: privacy, disabled-by-default recovery, disposable test accounts, tests for failure cases) and [HANDOFF.md](../HANDOFF.md) (the short state of the project for whoever, or whatever, picks it up next). Both are described below as answers to problems.

## The saved sessions

Three Pi session exports were reviewed. The numbers describe those exports only; messages, tool results and compactions measure different things, and none of them measures quality. The exports contain private context and are not published.

| Session | Recorded activity | What happened |
|---|---|---|
| First | 334 messages, 156 tool results, no compaction | Hardened the password change, corrected the length check on the current password and kept the unfinished recovery disabled. |
| Second | 1,762 messages, 878 tool results (8 advisor calls), 4 compactions | The long recovery session. The export ends mid-implementation and includes a local runner failure. |
| Third | 992 messages, 501 tool results (6 advisor calls), 1 compaction | Implementation, reviews and tests continued. The export ends during follow-up work, so it does not by itself prove that later phases were finished. |

## Problems we ran into

This is the part I wish I had read before starting. Each item says what happened, what it taught me and what I do about it now.

### 1. Long sessions, compaction and starting over

**What happened.** Sessions grew. One accumulated about **100 million input tokens**, almost all served from cache. That is the sum of very many calls, not the size of a single context window. When the context filled up, Pi *compacted* it: it summarised the earlier conversation and carried on. The second session was compacted four times.

**What it taught me.** A summary is a summary. After a compaction the model could lose a decision, a restriction or a test that was still pending, and would then confidently redo or contradict earlier work. Long histories also cost time and make mistakes harder to spot.

**What I do now.** I keep the important facts *outside* the conversation: [HANDOFF.md](../HANDOFF.md) for the state of the project, [AGENTS.md](../AGENTS.md) for the rules and git for the history. When a session gets heavy I start a fresh one and begin with: the goal, the branch, the decisions already taken, what is unfinished and the next safe step. Then I let the agent read the repository, not its memory of the repository.

### 2. The GPU runner crash

**What happened.** The Ollama/MLX runner on my Mac stopped with a Metal error reported as `Impacting Interactivity`. The session in progress was interrupted.

**What it taught me.** I could not trace it to a single cause. A smaller model, less context or less graphical load *might* help in diagnosing such a failure, but I have not verified any of those, and I do not claim a fix. What did help was not depending on the session: with a clear handoff, a new one could pick up within minutes.

### 3. Tests that pass while reality fails

**What happened.** Much of the early testing used stand-ins for Samba, for email and for Telegram. They let me move fast, but they only prove that the code does what *I think* the outside world does. The clearest case: the first version of the reset sent the new password through a pipe on a file descriptor, because the design assumed `smbpasswd` would read it from there. The real `smbpasswd` does not; `smbpasswd -s` reads the new password, twice, from standard input. The unit tests were green and the real reset would have failed.

**What it taught me.** Mock tests answer "is my logic consistent?", not "does the real thing agree?". Reviews and trials on a real, disposable Samba found a series of problems the fakes could not: the password transport above, parts of the web interface that were not connected to the new service, a wrong choice of channel and SQLite transactions that kept a write lock longer than they should.

**What I do now.** Anything that crosses a boundary (Samba, SMTP, Telegram, the operating system's user and socket permissions) gets at least one test against the real thing in a disposable container, and I write down in [TESTING.md](../TESTING.md) which layer each result comes from.

### 4. Bugs that reviews caught

Four defects were found in review rounds and fixed one by one, each with a test that fails without the fix:

- **The Telegram poller spun.** A "sleep" that did nothing meant the poller hammered the API in a tight loop, and an outage looked the same as "no messages". It now pauses, can be interrupted and backs off after failures.
- **A changed channel did not kill a link already sent.** If an administrator revoked a contact channel, an already-issued link kept working until it expired. Any add, change or revoke now invalidates the account's pending, approved *and* issued requests.
- **A volatile data directory.** The recovery ledger could end up under `/run` or `/tmp`, which does not survive a reboot. The authority now refuses to start there.
- **Settings that never reached the process.** Several configuration options were read but not passed on, so the portal enforced one policy and the authority another. A meta-test now checks that every setting is actually consumed.

### 5. Tests that tested nothing

**What happened.** A security test can "pass" because the thing it is meant to forbid never ran. A test that says "the portal cannot approve a request" is worthless if the request was never pending in the first place. Several rounds of review of the privilege-separation tests pushed them from "nothing bad happened" towards proofs that the action was really attempted and really refused.

**What I do now.** Security tests must be able to fail. The privilege-separation and chain tests include *non-vacuous* checks (the request is shown to be pending and still pending afterwards) and negative controls that are meant to fail, and [TESTING.md](../TESTING.md) says which ones.

### 6. Documentation drift

**What happened.** The project's documents repeatedly disagreed with the code: a test count that went stale, "not yet run" notes for things that had been run, and claims that went further than the evidence. Review rounds corrected these several times.

**What I do now.** Documents state *what was tested, on what, and what was not*, and avoid promises. The honest status ("experimental, not independently audited") appears in the README, in the security notes and in the operations guide.

### 7. Trusting the advisor

The advisor was called **14 times** across the two later sessions. Its answers were useful *proposals* for design and security questions, but they had to be checked against the code, the tests and real behaviour like anyone else's. It is not a security audit, and the project does not claim one.

## Practical tips if you try this

- **Start small and keep a handoff file.** Write down the goal, the rules and the next step in a file in the repository.
- **Make the agent run the tests**, and read the output yourself.
- **Test real boundaries** with disposable containers, never with real accounts.
- **Treat compaction as lossy.** If a decision matters, it belongs in a file.
- **Keep the set of tools small.** More extensions mean a heavier prompt and a slower local model.
- **Do not put secrets in prompts, profiles or repositories.** Use separate configuration for API keys.

## What this process does not prove

Pi, Qwen and the advisor are **not** a substitute for review. Samba Key should be judged on its code and on its [tests](../TESTING.md), not on which model wrote it. It remains experimental and has not been independently audited. Full transcripts can contain paths, identifiers, contact details or credentials, so they are kept outside the repository; if you publish logs or bug reports of your own, review and clean them first.
