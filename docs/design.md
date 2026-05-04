# Design

RavenWire uses the **Orbital Plasma** visual direction for the Config Manager web UI.

The goal is a tactical, deep-space operations interface that can carry dense Zeek, Suricata, sensor health, and packet-capture telemetry without eye strain. The UI should feel like a high-performance KDE Plasma-style security workstation: dark, crisp, structured, and built for long detection-engineering sessions.

## Palette

| Token | Use | Hex |
|---|---|---|
| Void Black | App background | `#0B0E14` |
| Plasma Slate | Cards, modals, panels | `#171A21` |
| Surface Highlight | Hover and active states | `#242933` |
| Precision Border | Hairline borders and table structure | `#2D323B` |
| Starlight Silver | Primary text | `#E2E8F0` |
| Muted Orbit | Secondary text, timestamps, headers | `#8B949E` |
| Arch Cyan | Primary actions, active navigation, baseline charts | `#1793D1` |
| Tactical Crimson | Critical alerts, disconnected sensors, dropped packets | `#F43F5E` |
| Sensor Green | Healthy sensors, active containers, successful enrollment | `#10B981` |
| Warning Amber | Warnings, degraded throughput, missing configuration | `#F59E0B` |

## Styling Rules

- Use Void Black for the application canvas and Plasma Slate for panels, cards, modals, and table shells.
- Use 1px Precision Border lines for structure instead of heavy shadows.
- Use subtle glow only for meaningful cyber/telemetry feedback, especially Arch Cyan actions and Tactical Crimson critical states.
- Keep large data surfaces quiet: muted table headers, compact spacing, strong row hover states.
- Use monospace text for sensor names, IP addresses, ports, certificate serials, rule names, file paths, hashes, and log-like values.
- Prefer Sensor Green, Warning Amber, and Tactical Crimson for status semantics. Do not use those colors decoratively.
- Avoid pure white text and large bright surfaces; Starlight Silver should be the brightest neutral.

## Tailwind Implementation

The theme is implemented in Config Manager through Tailwind:

- `config-manager/assets/tailwind.config.js` defines the `orbital.*` palette, monospace stack, and glow shadows.
- `config-manager/assets/css/app.css` applies the base theme and maps legacy utility colors into Orbital Plasma values during the migration.
- `config-manager/priv/static/assets/app.css` is the compiled stylesheet served by Phoenix.
- `config-manager/Dockerfile` runs the Tailwind build during the Config Manager image build.

Over time, prefer explicit Tailwind tokens such as `bg-orbital-slate`, `text-orbital-text`, `border-orbital-border`, `text-orbital-cyan`, `text-orbital-green`, `text-orbital-amber`, and `text-orbital-crimson` instead of relying on the compatibility mappings for older `gray-*`, `blue-*`, `green-*`, `yellow-*`, and `red-*` classes.

## UX Direction

The dashboard should stay a quick-glance fleet health view. Dense tables, raw telemetry, detailed capture counters, and action controls belong on detail pages.

Sensor cards should answer:

- Is the sensor reporting?
- Is it healthy or degraded?
- How fresh is the telemetry?
- Are disk, CPU, memory, drops, or clock health concerning?
- Where do I click for the full investigation view?

Detail pages should preserve richer operational context: host readiness, containers, capture pipeline, storage, clock, forwarding, and operator actions.
