# TwinShield

A local warning tool for lookalike Wi-Fi hotspots ("evil twins").

It scans nearby access points, compares them with a network baseline **you** approve, and shows each suspicious finding with its evidence and a review score on a dashboard that runs on your own machine.

It reports suspicious evidence. It does not prove an attack, and the score is a review priority, not a probability.

## Run it

Needs Python 3.8 or newer. Nothing to install.

```
python3 -m twinshield serve          # then open http://127.0.0.1:8787
```

Scanning uses NetworkManager (`nmcli`) on Linux and `netsh` on Windows. Recent macOS versions removed the built-in scan tool, so use Linux or Windows for live scans.

1. Start it and let it complete two scans.
2. In **Approved baseline**, tick the networks you own or are authorised to manage and approve them.
3. From then on, every scan is compared with that baseline.

No hardware at hand? `python3 -m twinshield serve --replay` replays a labelled test fixture so you can see every alert type.

## What it checks

| Evidence | Points |
|---|---|
| Unfamiliar radio using an approved network name | 45 |
| Weaker security than the approved network | 35 |
| Security downgrade on an approved radio | 50 |
| Name one small edit from an approved name (lookalike) | 30 |
| Weaker security than the lookalike target | 25 |
| Much stronger than every approved radio | 10 |
| Channel or band not seen for an approved radio | 12 each |
| Unusual signal for an approved radio | 8 |

Repeated sightings fold into one incident. A single sighting is capped at "Review"; "Strong suspicious evidence" needs a score of 60 or more and at least two sightings. An owner changing channel stays low on purpose, to avoid false alarms.

## Safety and privacy

- Reads access-point metadata only: name, radio address, channel, signal, advertised security.
- Never captures traffic, collects credentials, or disconnects anyone.
- The dashboard binds to 127.0.0.1 and rejects cross-origin writes. Baseline and a bounded alert log are stored in `~/.twinshield`.

## Limits

- A copied radio address with identical security and a believable signal can look genuine to a metadata-only check.
- One adapter sees only what is in range, and signal moves with people and walls.
- Rules only. There is no learned model, so there is no claim about one.
- Live scanning is tested through its parsers and a fixture; verify it on your hardware.

## Tests

```
python3 -m unittest tests.test_twinshield
```

The public demo at the project site replays the test fixture. It is not a scan of your network.
