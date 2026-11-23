# TwinShield

A local review desk for lookalike Wi-Fi hotspots.

TwinShield reads nearby access-point metadata, compares it with a baseline you approve and shows the evidence behind each finding. A familiar network name is not enough to identify its radio. A finding is a reason to investigate, not proof of an attack. Review scores are priorities, not probabilities.

Live fixture: https://twinshield-five.vercel.app/

## Run locally

Python 3.8 or newer. No Python packages to install.

```sh
git clone https://github.com/Aditya2375/twinshield
cd twinshield
python3 -m twinshield serve
```

Open `http://127.0.0.1:8787`. Wait for at least two completed scans, then approve only networks you own or are authorised to manage. Approval replaces the baseline using recent observations. New scans are compared with that baseline.

- Linux scanning needs NetworkManager's `nmcli`.
- Windows scanning uses `netsh`.
- Recent macOS versions do not have the required built-in scanner. Use Linux or Windows for hardware scans.
- Hardware and OS permissions must be checked on your own machine.

For an isolated, labelled example with no hardware scan:

```sh
python3 -m twinshield serve --replay
```

The local replay server advances its own fixture observations. It is labelled as replay, not live scanning. Baseline approval and acknowledgment controls are only available in live mode.

## The public fixture lab

The hosted page does not access a local scanner. It loads `demo.json`, starts paused at the repeated-sighting example and labels all observations as fixture data. Chapter buttons and a cycle slider examine the full 24-observation sequence. Playback starts only when you choose it, stops at the end and pauses when the tab becomes hidden.

Signal plots show channel and adapter-reported percentage, separated by band. They are not physical location, distance, channel width, packet traffic or interference measurements. Out-of-range channel metadata is omitted from the plot with a notice and remains in the inventory. The plot, radio inventory and evidence inspector share the same selected radio. Search finds network names and radio addresses.

To preview the fixture with any static server on localhost, add `?demo=1`. Without that parameter, localhost first looks for the Python API. A missing API route permits the labelled fixture preview; an unavailable, invalid or timed-out local API does not silently become a demo.

## Evidence rules

| Observation                                        | Review points |
| -------------------------------------------------- | ------------: |
| Unfamiliar radio using an approved name            |            45 |
| Weaker security than that approved network         |            35 |
| Security downgrade on an approved radio            |            50 |
| Name one small edit from an approved name          |            30 |
| Weaker security than that lookalike target         |            25 |
| Much stronger than every approved radio            |            10 |
| Channel or band not recorded for an approved radio |       12 each |
| Unusual signal for an approved radio               |             8 |

The score is capped at 100. A score of at least 60 needs two sightings to be labelled **Strong suspicious evidence**. One sighting is capped at **Review**. Repeated observations are folded into an incident. Acknowledgment records that you saw the evidence; it does not lower the score or make a radio safe.

## Limits, privacy and local storage

- Reads network name, radio address, channel, signal and advertised security. It never captures traffic, collects credentials or disconnects anyone.
- A copied address with matching security and a plausible signal can evade metadata-only comparison.
- One adapter sees only radios in range. Walls, people and maintenance can change signal, channel and band. No findings is not proof of safe Wi-Fi.
- The local server binds to `127.0.0.1`, checks loopback Host on reads and writes, rejects cross-origin writes, requires bounded JSON requests and serves a static allowlist.
- Baseline and a bounded incident log stay in `~/.twinshield`. `TWINSHIELD_HOME` selects another storage folder, useful for tests. Corrupt JSON and malformed baseline structures are rejected instead of entering the rule engine.
- Baseline approval needs observed named networks, at least two completed scans and a fresh available scanner. Failed saves preserve the prior baseline.
- Unavailable scanner contact marks prior observations stale and disables baseline approval and acknowledgment. Writes are not automatically retried after uncertain results.
- Public fixture playback makes no API writes or third-party requests. Fonts are self-hosted. Network responses have an 8-second client deadline and a 2 MB streaming limit.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover parsers, rule thresholds, repeated sightings, fixture behavior, bounded incidents, malformed local records, save failures, stale approval refusal and local HTTP Host/origin/content/size/static-path boundaries. Tests use fixtures and temporary storage, not a hardware scan or real network approval.

The optional `_review/` folder in the staged review ZIP contains browser checks, screenshots and test logs. It is not part of the deployed site. Browser checks require `playwright-core` and Chrome, with `CHROME_BIN` as an override. They are Chromium checks, not a claim of cross-browser or assistive-technology certification.

## License and credits

Project code: MIT, Aditya Kulkarni. Original, unmodified Manrope fonts are self-hosted under the SIL Open Font License in `assets/font-licenses.txt`. Interface mark and share artwork are original to this project. See `DESIGN.md` for the interface study, decisions and reference limitations.

Support: adityakulkarnicoding@gmail.com
