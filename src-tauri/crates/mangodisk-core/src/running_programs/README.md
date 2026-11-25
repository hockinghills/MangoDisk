# Running-programs triage: questions, exports and the CLI

The Running programs page can ask a decision model about each program it found. The model
scores fixed options from a short list of facts. It does not write text, so a whole machine
costs a few cents. This page covers the parts meant for review and automation:

- **The question file** sets what the model is asked.
- **The export** holds every program, the facts the model saw, the measured costs and every
  answer, in Markdown or JSON.
- **The CLI** runs the scan and the triage from a terminal, or from an agent such as Claude
  Code, and prints the export.

Triage is advisory. Nothing here stops or removes anything.

## What the model sees

For each program that is not a core component, MangoDisk sends the program's name and
process names, plus these facts when they are known:

- its package and description
- how and roughly when it was installed (for example "with pipx", "more than a year ago")
- its location, with the home folder shortened to `~`
- what starts it
- how many installed packages depend on it
- whether it has been almost idle since it started

Command lines, environment variables, file contents, memory and CPU figures are never sent.
The export's `facts` object for each program is exactly what was sent.

Each choice question is asked twice, with its options in opposite orders, and the two sets of
probabilities are averaged. This cancels the bias many models have toward the first option.
`ordersAgree: false` marks programs where the two orders picked different answers; treat those
with care. Score levels always go lowest first, so they are not reversed.

## The question file

The built-in questions are used until a file named `triage-questions.json` exists in MangoDisk's
data folder. On Linux that folder is `~/.local/share/app.mangodisk.desktop/data/`.

To start from the built-in set, either:

- choose **Edit questions** on the Running programs page, which writes the file and shows it in
  your file manager, or
- run `mangodisk running-programs questions --write-template`.

Neither one overwrites an existing file. Delete the file to go back to the built-in questions.

```json
{
  "schemaVersion": 1,
  "questions": [
    {
      "id": "role",
      "type": "choice",
      "instructions": "What is this program's role on this computer? Judge only from the facts given about the program.",
      "options": [
        { "id": "tool", "criterion": "An application, tool or service a person installed on purpose and still uses" },
        { "id": "leftover", "criterion": "Installed for a past task, an experiment or by an install script, and not needed by anything in use now" }
      ]
    },
    {
      "id": "miss",
      "type": "score",
      "instructions": "If this program stopped and never started again, how much would the person who uses this computer notice?",
      "levels": ["Nothing anyone uses would change", "Something used every day would break"]
    },
    {
      "id": "autostart",
      "type": "noul",
      "instructions": "This program starts on its own at login or boot"
    }
  ]
}
```

### Question types

| Type | What the model returns | Fields |
|---|---|---|
| `choice` | one option, with a probability for every option | `options`: 2–32 `{ id, criterion }` |
| `score` | a probability for each level, and the expected level | `levels`: 2–10 strings, lowest first |
| `noul` | the probability that `instructions` is true | none |

### Limits

- `schemaVersion` must be `1`.
- 1 to 8 questions.
- Question and option ids use only `a-z`, `0-9` and `_`, and are at most 40 characters.
- Ids are unique: questions within the set, and options within their question.
- Every instruction, criterion and level is at most 600 characters, on one line.
- The file is at most 256 KB.

`mangodisk running-programs questions --check FILE` names the first rule a file breaks. The page
also shows the problem under the export buttons, and triage will not run until the file is fixed
or removed.

### How the page uses answers

- A `role` choice question whose option ids are all built-in (`desktop`, `needed`, `tool`,
  `leftover`, `unclear`) drives the row labels and the **Leftovers** filter.
- A `miss` score question with exactly five levels drives the "If it stopped" line.
- Any `role` question with a `leftover` option drives the **Leftover weight** sort: footprint
  times the probability of `leftover`.
- Every other answer appears in the row's details under its own question id. The first choice
  answer becomes the row's chip when there is no built-in role.

## The export

Choose **Export Markdown** or **Export JSON** on the page, or use the CLI. Without a triage,
the export still lists every program and its facts, so you can review what would be sent.

A new scan clears the last triage. Its answers judged the earlier facts, and exporting them
beside new costs would mix the two scans.

### JSON shape (`schemaVersion: 1`)

```jsonc
{
  "schemaVersion": 1,
  "generator": "MangoDisk running-programs triage export",
  "capturedAt": "2026-11-25T03:23:14Z",
  "notes": ["..."],                    // how to read the answers
  "triage": {                           // null when no triage ran
    "model": "vendor/model",
    "questionSource": "builtIn",        // builtIn | file | supplied
    "questions": { "schemaVersion": 1, "questions": [ ... ] },
    "inputTokens": 1800,
    "costUsd": 0.0002,
    "judgedCount": 9,
    "failedCount": 0
  },
  "programs": [
    {
      "id": "ManualOpt:/opt/example:example",  // stable across scans; use with --only
      "name": "example",
      "package": null,
      "safetyClass": "yours",                  // core | system | optional | yours
      "judged": true,
      "facts": { ... },                        // exactly what the model received
      "cost": {
        "memoryKb": 201559, "swapKb": 0, "memoryIsProportional": true,
        "cpuPercentNow": 0.0, "cpuPercentAverage": 0.7, "processCount": 1
      },
      "answers": {
        "role": { "type": "choice", "choice": "leftover", "confidence": 0.62,
                  "probabilities": { "leftover": 0.62, "tool": 0.2, ... }, "ordersAgree": true },
        "miss": { "type": "score", "expected": 0.8, "probabilities": [0.4, 0.4, 0.2, 0, 0] },
        "autostart": { "type": "noul", "probability": 0.77 }
      },
      "leftoverWeightKb": 124966.6,            // footprint × P(leftover), or null
      "error": null                            // a decision error code when the requests failed
    }
  ]
}
```

Programs are sorted by `leftoverWeightKb`, then by footprint.

## The CLI

Build the CLI with `pnpm cli:build`. The binary is `target/release/mangodisk`. It uses the
decision-model connection saved by the desktop app; the API key is read from that file and is
never printed.

```sh
# What a triage would send, without sending anything
mangodisk running-programs scan > programs.md

# Triage with the saved model and the active questions; Markdown on stdout, progress on stderr
mangodisk running-programs triage > triage.md

# The same export as JSON
mangodisk --format json --no-progress running-programs triage > triage.json

# Try a question file for one run without making it the active set
mangodisk running-programs triage --questions my-questions.json > try.md

# Compare another model on the same questions, or re-judge only some programs
mangodisk running-programs triage --model vendor/other-model
mangodisk running-programs triage --only 'ManualOpt:/opt/example:example' --only 'NpmGlobal:...'

# Read administrator-only process details through the desktop's password prompt
mangodisk running-programs triage --administrator-rights

# Show, check or create the question file
mangodisk running-programs questions
mangodisk running-programs questions --check my-questions.json
mangodisk running-programs questions --write-template
```

With `--format json`, the CLI wraps the export as `{ "schemaVersion": "1.0", "command": ...,
"data": <export> }`. Paths in `path` fields are shortened unless you pass `--include-full-paths`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success |
| 3 | failure; the message says why |
| 5 | another triage or scan is already running |
| 6 | the provider rejected the API key, or permission was denied |
| 7 | cancelled with Ctrl+C or at the password prompt |
| 8 | the triage finished, but some programs could not be judged |

Each judged program costs two requests. `--only` and a short question set keep reruns cheap.

## Reviewing a triage with another model

One way to have a stronger model check the triage:

1. Run `mangodisk --format json --no-progress running-programs triage > triage.json`.
2. Give the export to the reviewer, for example Claude Code in this repository. Ask it to
   check each answer against that program's `facts`, and to flag programs where `ordersAgree`
   is false or confidence is low.
3. Let it propose sharper questions in a new file. Check the file with `questions --check`,
   then rerun with `--questions` and `--only` for the programs it questioned.
4. Compare the two exports before you act on either.

The reviewer sees only what the export holds. It cannot tell whether you still use something,
so treat its notes as questions to answer, not verdicts.
