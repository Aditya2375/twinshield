# TwinShield: a wireless review desk

## Direction, before implementation

A calm, blue-and-white instrument, not a threat-themed landing page. A narrow deep-blue navigation rail, rounded control surfaces, pale-blue graph paper and small, precise channel plots give this project its own identity. Manrope carries the interface; monospace is reserved for radio addresses and commands. No serif hero, warm accent, code-editor specimen or decorative radar.

The product is a local Wi-Fi metadata comparison tool. The interface should make its central distinction visible: an approved network name is not the same thing as an approved radio. Show actual baseline, radio, security and repeated-sighting evidence before asking a visitor to read documentation.

## Inspected references

- https://www.oscium.com/products/inssider/ : inspected the product page and its rendered application screenshot. The useful pattern is the linked access-point table and channel/signal display, not the sales layout. TwinShield does not measure channel width or interference, so it must not borrow spectrum envelopes that imply those measurements.
- https://www.intuitibits.com/products/wifiexplorer/ : inspected the page structure, but its lazy-loaded screenshots stayed transparent placeholders in this session. Its missing product pixels did not inform the design.
- https://twinshield-five.vercel.app/ : inspected the current public fixture dashboard. The large radar implies spatial knowledge the tool does not have, labels collide, and useful details sit below a large blank alert panel. Replace it with actual channel/signal coordinates and a useful first fixture state.

## Composition and behavior

- Persistent source label: fixture data, never a scan of the visitor's Wi-Fi. No fake connected indicator, live timestamp or claimed protection.
- The public fixture starts paused at its repeated-sighting example. A labelled chapter strip and a 24-cycle scrubber let visitors inspect the full sequence. Play is explicit, including with reduced motion.
- Signal plots use reported percentage and channel, separated by frequency band. They show no invented distance, bearing, bandwidth, packet activity or confidence. Clicking a radio links the plot, table and evidence inspector.
- Review score means priority, not probability. A single sighting remains review-level. A known radio changing channel remains low priority.
- The local server retains real baseline approval and acknowledgment. Public fixture controls never call write endpoints. Lost contact must make data stale, not reassuring.
- Motion is restrained: short selection transitions and explicit fixture playback. No autonomous radar sweep. Reduced motion removes transitions.

## Trust and implementation constraints

Preserve the MIT attribution to Aditya Kulkarni, deterministic Python rules, loopback host/origin protections and dependency-free local runtime. Self-host the original, unmodified Manrope font with its OFL notice. Keep source text inert. Add a keyboard-usable help dialog with full background isolation and exact focus return. Ship no development-attribution copy or invented customer claims. Keep all review material out of deployment.

## Verification plan

Check desktop, tablet, 390px and 320px; public fixture and isolated local replay server; all fixture chapters; plot/table selection; filter state and focus; modal repeated forward/reverse Tab and invoker return; failed, malformed and delayed API responses; baseline approval and ack using temporary test storage only; no real hardware scan; no public POSTs; no third-party requests; all Python tests and HTTP boundary tests. Inspect actual rendered pixels before critic handoff. Stage only, no push.
