# Gen5 stall and factory-reset reproduction plan

Prepared 2026-11-05; resumed 2026-11-06. This protocol is being exercised on
**this Gen5 with a fresh, unfunded test wallet**, confirmed by the operator.
The [dated evidence report](gen5-reset-20261106.md) separates completed cases
from untested conditions. Keep ordinary hardware acceptance and signing suspended.

## Question and current evidence

Determine whether the device first freezes at the prompt to open **SHRINCS HW
Check**, whether that depends on prior app activity, and whether the subsequent
power-button hold precedes a reboot, Protection mode, or factory initialization.
Separate those observations instead of treating every lost USB response as a
factory reset.

The operator clarified that the last screen was asking permission to open the
HW app and was unresponsive. They held power for approximately **10–15 seconds
because nothing worked**, then saw initialization pages asking for a name and
PIN. The exact prompt wording and its timing relative to host commands were not
captured. Here, "locked" describes the reported frozen screen; it does not
establish that it was a PIN-lock screen.

Earlier host reports show successful diagnostic computations followed by a
failed resource check: 1,640 bytes of stack headroom against a 4,096-byte target.
The last recorded host operations were app exit (success) and a version query
returning `5515`. No factory-reset command was sent, and no final original-wallet
snapshot exists. See the [incident record](../hw-check/README.md#stall-and-reset-incident).
The low stack margin is a separate observed failure, not a proven reset cause.

Ledger documents settings/PIN reset paths and a Protection-mode process that can
end in reset and recovery setup. A held power button alone is not a documented
factory-reset procedure. Neither a Protection-mode message nor three incorrect
PIN entries was reported. Use these as possible classifications, not diagnoses.
Sources: [Ledger's Gen5 manual, mirrored copy](https://device.report/m/70081e17b48cbb95b4d4361d1b8542a39b3c8698254948f69623f9e7c1797892),
[Ledger power-off/restart guidance](https://support.ledger.com/article/360025864773-zd).

## Stage 1: preserve evidence and prepare the observer offline

Freeze the existing `20261105-hw-check/` evidence without overwriting it.
Archive the source base, current tracked diff and untracked source, dependency
pins, host scripts, installation APDUs, Docker image identity, and ELF hashes.
The incident ELF is:

```text
48768fecbfc74e76df2a3a8f0378933ef0198504db4a15fb4f624556e6f63781
```

Compare any rebuilt artifact to that archived ELF; a newly built file with the
same app version is not automatically the same experiment. Label source/script
revisions separately, since the recorder changed after the initial creation
report omitted its post-operation snapshot.

Before physical replay, prepare a host runner with these properties:

- One explicitly selected USB device, one client, and one reader. Ledger Live
  and other clients are closed during tests. No background launch/version probes.
- Append and flush an event record **before sending each APDU**, then record
  response/status, monotonic elapsed time, UTC, and transport errors. Open the
  evidence file before connecting. A timeout or killed native HID read must
  leave a useful partial record; the current final-JSON-only reporter cannot
  guarantee this.
- Separate `launch`, `read`, `permission probe`, `create`, `recompute`,
  `busy-probed recompute`, `verify`, and `exit` into individually selected steps.
  The current `benchmark --samples 1` also runs a second keygen with probes, so
  it is unsuitable for a genuine single-operation control without modification.
- No automatic retry, reopen, reinstall, reset, or next experiment on failure.
  Bound computation at 120 seconds and ordinary public reads at 10 seconds;
  keep manual launch/approval waiting distinct from a failed read.
- Record start/end snapshots and metrics when responsive. Public status,
  commitments, page digests, and counters suffice; no secret exports or RAM dumps.

Inspect the exact SDK/app code offline: StackTracker initialization and paint
bounds, linker stack/heap regions, large stack frames and nested callbacks,
NBGL object/string lifetimes and home redraws, event handling during lock/exit,
the derivation shim/probes, and the host launch/exit command path. An app-launch
prompt alone does not prove whether app initialization has started; establish
that ordering from the SDK/OS evidence before making causal claims. Run relevant
emulator tests for the observer and protocol boundaries; Speculos success does
not establish physical watchdog, lock, or Protection-mode behavior.

## Stage 2: establish the disposable device and observation setup

Use a newly generated, unfunded wallet on this Gen5. Do not restore the original
wallet seed for reproduction. Keep the test backup private; no funding or
signing is needed. A repeat wipe is an anticipated possible outcome of this
experiment, not an accepted outcome for the application.

Record OS/MCU versions, model, battery level, power source/cable, installed apps,
Bluetooth/NFC settings, auto-lock/auto-power-off settings, host package versions,
and USB node. Preserve LedgerOS 1.1.1 / MCU 8.1.2 if still present; an OS update
would be a separate comparison, not an identical replay. Do not downgrade.
Unknown original settings remain unknown rather than being filled in by guess.

Synchronize host logs with an external camera/stopwatch showing the screen and
button actions. Do not record setup/recovery words or PIN entry. Pause recording
for those steps and mark the gap. Log each tap, visible response, and exact
button-down/button-up time. An unchanged E Ink image or an APDU awaiting human
approval alone is not evidence of a freeze.

Before each independent case, record its initial state: dashboard/app, EMPTY or
READY, boot nonce, and whether an app restart or full power cycle occurred.
Separate cold-launch cases from continuous-session cases. Key generation uses
fresh device randomness; replay the same operations, not the previous private
key. A new seed alone is insufficient to reconstruct old SHRINCS NVM state.

## Stage 3: isolate launch, lock, and exit before key generation

Run each applicable case once first. Repeat a clean case up to three times only
when necessary to compare it with a failure. Avoid a large Cartesian stress
matrix. Keep the cable, OS, and settings fixed unless that row changes them.

| Case | Controlled operation | What it distinguishes |
| --- | --- | --- |
| L0 | Dashboard lock/unlock and normal menu power-off/on, with no developer app running | Basic OS/UI behavior and retained disposable-wallet setup |
| L1 | Launch a minimal developer app built with the same SDK, accept/reject its opening warning, then exit; no SHRINCS workload | Developer-app confirmation path and SDK baseline |
| L2 | Install the archived HW Check ELF; manually launch and reject its opening prompt, then separately launch and approve; no key creation/probes | HW Check launch/initialization versus later workloads |
| L3 | Leave the opening prompt visible until the recorded auto-lock interval, then try one documented unlock/resume action | Pending launch confirmation interacting with locking |
| L4 | From a responsive idle HW Check, use its on-device exit, then reopen; separately compare host `B0 A7` exit and reopen | Device-driven versus host-driven exit/relaunch |
| L5 | Repeat a launch through the host only if that launch mechanism is verified and relevant to the original sequence | Manual versus host-driven launch; no invented historical APDU |

Record the actual prompt text and whether an explicit tap is acknowledged.
If L2/L3 reproduces a freeze before any keygen, prioritize that smaller case.
Do not assume keygen is responsible merely because it previously used more
stack. App initialization can still derive the app key and inspect NVM.

## Stage 4: separate the freeze from the power-button response

Use one baseline hold on a **responsive dashboard**, then compare it with a hold
only after a captured freeze if one occurs. Time the hold, releasing immediately
when the device visibly powers off or restarts; otherwise stop at 15 seconds.
Record the actual duration rather than insisting on 15 seconds after a state
transition. This reproduces the operator's reported recovery action; it is not
an assertion that Ledger specifies a particular forced-restart duration.

For a suspected freeze, first record the visible screen and the last successful
host event. Make at most one attempt at an applicable visible Approve/Reject
control and allow 10 seconds to observe a response. Do not tap PIN digits as a
responsiveness probe. Do not send a second request while another is outstanding.
Stop the host runner before the recovery hold and mark that time. Do not insert
a power hold into an otherwise progressing keygen or an active NVM write; that
would be a different fault-injection experiment.

Capture the entire subsequent screen sequence without new host requests:
ordinary boot/PIN, app exit, developer warning, Protection mode/error/progress,
or initialization/name/PIN setup. If Protection mode starts, preserve its text
and progress and stop the test sequence; do not deliberately interrupt it.
A settings reset and three-wrong-PIN reset are **not** reproduction steps here.

## Stage 5: add workload history only if launch controls are clean

Use the same observation procedure after each operation, checking public state
and an exit/reopen transition. Separate independent launches first, then retain
one continuous-session replay if cumulative history remains a plausible factor.

| Case | Added history before the relevant launch/exit/lock transition |
| --- | --- |
| W1 | Public reads only; separately ordinary creation rejection |
| W2 | Each permission probe individually; then the seven-probe sequence only if needed |
| W3 | One approved creation from EMPTY; no recomputation afterward in this case |
| W4 | One recomputation of an existing diagnostic identity, with no busy probes |
| W5 | One recomputation with the four early busy probes |
| W6 | One canonical 4 KiB verification, expected Invalid verdict |
| W7 | At most one original-history replay: permissions, rejection, creation, three plain recomputations, one probed recomputation, maximum verification, exit, then the relevant launch prompt |

W7 is conditional on the simpler cases not reproducing the fault and on review
of their evidence. Preserve actual delays/lock settings where known; the old
report timestamps cannot reconstruct unrecorded UI actions or exact completion
times. Do not silently infer that the later launch prompt was SHRINCS Lab when
the operator remembers HW Check.

The archived build already fails the stack target after creation. Testing that
build is an explicitly bounded **incident reproduction**, never resource
acceptance. Keep `resource_passed=false`; do not lower the 4 KiB bound, suppress
the failure, or let the normal acceptance runner continue automatically.
Stop further work in the case on any new headroom drop below the recorded 1,640
bytes, invalid metrics, unexpected state/write change, timeout, freeze, reset,
or Protection-mode indication. Do not continue the remaining workload sequence
after the incident has appeared. Lower-workload controls must precede W7.

## Stage 6: discriminate causes and define the result

Preserve the first reproduction before recovery or reinstallation. Minimize by
removing preceding operations or changing one relevant factor: app launch path,
auto-lock crossing, busy probes, permission probe, or exit method. Introduce
instrumentation only after testing the unchanged archived ELF; label every
variant by hash because instrumentation changes stack/layout and timing.
If necessary, compare metrics-enabled versus disabled builds, or a smaller-stack
implementation, using the same minimal sequence. Neither improved stack usage
nor one successful run proves that the reset cause was fixed.

| Observation | Report classification |
| --- | --- |
| UI/USB resumes without boot or identity change | Temporary delay or transport/UI issue; not a reproduced reset |
| App restarts, diagnostic boot nonce changes, OS wallet remains initialized | App/device restart; no demonstrated factory reset |
| Explicit Protection-mode screen/progress | Protection-mode observation; record whether initialization follows |
| Previously initialized device returns to name/new-PIN/wallet setup | Factory-reset symptom reproduced; internal cause still needs evidence |
| No failure in the bounded cases | Not reproduced under the recorded conditions; not proof of safety |

On the first factory-reset/Protection-mode observation, stop the broader matrix
and preserve the evidence. A second minimal replay should follow analysis, not
automatic retries. Build a reviewable Ledger-support packet containing the
minimal steps, video with secrets excluded, firmware/SDK/app hashes, APDU event
timeline, expected/actual behavior, and uncertainties. Do not send it without
the user's instruction.

Completion for this investigation means a documented minimal reproducer or an
explicit bounded non-reproduction result, with freeze and wipe classified
separately. A candidate fix requires the same case to pass repeatedly and normal
regressions to pass; 4 KiB physical stack headroom and final uninstrumented
acceptance remain separate gates. Original-wallet recovery and stateful signing
are outside this reproduction protocol.
