# Design System Strategy: The Sovereign Ledger

## 1. Overview & Creative North Star
The Creative North Star for this design system is **"The Sovereign Ledger."** 

In the high-stakes world of enterprise cybersecurity, visual noise is a liability. This system rejects the "dashboard-as-a-cockpit" cliché of flashing lights and neon accents. Instead, it adopts a high-end editorial aesthetic that communicates quiet authority, permanence, and precision. We treat security data not as a series of alerts, but as a prestigious record of truth. 

By leveraging intentional asymmetry, sophisticated tonal layering, and an aggressive "no-line" philosophy, we move beyond the standard SaaS template. The result is a platform that feels less like software and more like a bespoke, high-fidelity instrument for the modern security architect.

---

## 2. Colors & Surface Philosophy
The palette is rooted in deep architectural tones—Navy, Slate, and Charcoal—offset by precise Teal accents that act as "the investigator’s light."

### The "No-Line" Rule
To achieve a premium editorial feel, **1px solid borders are strictly prohibited for sectioning.** Structural boundaries must be defined solely through background color shifts. For example, a `surface-container-low` (#ecf4ff) sidebar should sit adjacent to a `surface` (#f7f9ff) main content area without a stroke between them.

### Surface Hierarchy & Nesting
Depth is achieved through the physical stacking of tones:
*   **Base:** `surface` (#f7f9ff) is the canvas.
*   **Grouping:** `surface-container-low` (#ecf4ff) creates logical zones.
*   **Prominence:** `surface-container-lowest` (#ffffff) is reserved for the primary data cards or interactive surfaces, creating a "lift" through purity rather than shadow.
*   **The Signature Texture:** For primary CTAs and hero headers, utilize a subtle linear gradient from `primary` (#051125) to `primary_container` (#1b263b). This provides a "brushed steel" depth that flat color cannot replicate.

### Glass & Gradient Implementation
Floating utilities (like command palettes or hover-menus) should use a **Glassmorphism** effect. Apply `surface_container_lowest` (#ffffff) at 80% opacity with a 20px backdrop-blur. This ensures the UI feels integrated and layered rather than "pasted on."

---

## 3. Typography: The Editorial Scale
We pair **Manrope** for authoritative statements with **Inter** for dense, technical data.

*   **Display & Headlines (Manrope):** These are the "Editorial Voice." Use `display-md` or `headline-lg` with tight letter-spacing (-0.02em) to create a sense of density and power. Use `primary` (#051125) for high-contrast titles.
*   **Titles & Body (Inter):** These are the "Operational Voice." Use `title-md` for bounty names and `body-md` for vulnerability descriptions. The high x-height of Inter ensures legibility when scanning complex security logs.
*   **Labels (Inter):** Reserved for metadata (e.g., CVE codes, timestamps). Use `label-md` with `on_surface_variant` (#45474d) to create a clear visual distinction from the primary data.

---

## 4. Elevation & Depth
In this design system, shadows are secondary; **Tonal Layering** is primary.

*   **The Layering Principle:** Place a `surface-container-lowest` card on a `surface-container` background. The subtle shift from `#ffffff` to `#e2efff` creates a sophisticated "soft lift" that feels architectural.
*   **Ambient Shadows:** Where floating elements (like Modals) are required, shadows must be hyper-diffused. Use a 32px blur with 6% opacity. The shadow color should be a tint of `on_surface` (#0e1d29) rather than pure black to maintain color harmony.
*   **The Ghost Border Fallback:** If a border is required for extreme accessibility needs, use a **Ghost Border**: `outline_variant` (#c5c6cd) at 20% opacity. 100% opaque borders are forbidden.

---

## 5. Components

### Cards & Data Tables
*   **Structure:** Forbid divider lines. Use `surface-container-high` (#daeafc) background strips for table headers and `surface-container-low` (#ecf4ff) for alternating row depth.
*   **Spacing:** Use generous vertical white space (1.5rem to 2rem) to separate bounty items. Whitespace is the "separator," not a line.

### Buttons
*   **Primary:** A solid block of `primary` (#051125) with `on_primary` (#ffffff) text. Use `sm` (0.125rem) or `md` (0.375rem) roundedness for a sharper, more professional "B2B" edge.
*   **Secondary:** `surface-container-highest` (#d5e4f6) background. No border.

### Status Badges (The Teal Accent)
*   **Bounty Status:** Use the `tertiary` (#001417) scale for "Active" or "Verified" statuses. A `tertiary_container` (#002b30) background with `tertiary_fixed` (#9ff0fb) text creates a high-contrast, security-focused glow without being "neon."

### Input Fields
*   **State:** Default inputs use `surface-container-low` (#ecf4ff) with no border. On focus, transition to `surface_container_highest` (#d5e4f6) with a subtle `primary` (#051125) bottom-only accent line (2px).

### Custom Component: The "Threat Matrix"
For cybersecurity context, create a 2x2 grid using asymmetrical tile sizes (e.g., 60% width for the primary metric, 40% for the secondary) to break the "standard dashboard" feel.

---

## 6. Do’s and Don’ts

### Do:
*   **Do** use asymmetrical layouts. A 1/3 and 2/3 column split feels more editorial than a 50/50 split.
*   **Do** use `surface-dim` (#ccdced) for disabled states to maintain the cool, slate-heavy aesthetic.
*   **Do** emphasize "Data Density." Cybersecurity professionals prefer seeing more data in a clean Inter font over large, bubbly UI elements.

### Don’t:
*   **Don't** use a shadow and a border at the same time. Choose one (preferably neither).
*   **Don't** use standard "Success Green." Use the `tertiary` teal scale to maintain the system's professional B2B identity.
*   **Don't** use `xl` or `full` roundedness for primary components. Stick to `sm` or `md` to keep the interface feeling "technical" rather than "consumer-friendly."