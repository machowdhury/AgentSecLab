# UI review — Threat Modeling & Security Architecture

**Date:** 2026-09-25
**Status:** staged browser review complete

## Information architecture

The workbench uses five progressive surfaces:

1. Foundations;
2. System · Architecture;
3. Model · Analyze;
4. Architect Challenge;
5. Path B · Review.

It uses one bounded architecture and avoids a general graph engine, giant form, decorative SOC interface, and excessive cards. The primary content is readable markdown with no live search dependency.

## Answer gating

The first four tabs provide method, evidence, prompts, and hints. Reference conclusions appear only in Path B. This is pedagogical gating, not access control; Studio tabs can be opened directly and progress is not persisted.

## Accessibility design

- semantic headings and lists;
- text alternatives for the bounded architecture;
- no color-only state;
- no markdown pipe tables in Studio;
- native tab keyboard behavior and visible focus inherited from Splunk;
- no custom JavaScript.

Screen-reader status remains `PARTIAL` unless separately tested with assistive technology.

## Measured browser result

- 1920, 1440, 1280, and 1024 CSS-pixel viewports: no horizontal overflow observed.
- 1024 physical-pixel equivalent at 200% zoom (512 CSS pixels): horizontal overflow observed.
- All five tabs rendered.
- Keyboard focus moved from Foundations to System · Architecture with ArrowRight.
- Focus styling was visible through Splunk's inset blue focus treatment.
- Reference conclusions were absent from the first four tabs and the Path B warning was visible.
- Academy Home exposed L7, the challenge, and Capstone as the last LIVE launcher.
- Copy controls: not applicable; static text remains natively selectable.
- Dynamic error states: not applicable; this workbench has no search or data-source dependency.

## Accessibility conclusion

`PARTIAL`. Keyboard tab navigation and visible focus were observed. No horizontal overflow was observed at the four requested ordinary widths. The 200% reflow equivalent overflow is a known Splunk native-chrome/minimum-width limitation and remains unresolved. Screen-reader behavior was not tested.

Evidence: `docs/screenshots/threat-modeling/final_validation.json` and associated screenshots.
