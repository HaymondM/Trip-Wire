# Trip Wire

**Spot the hidden traps set for your AI.**

Trip Wire is a Chrome extension that reveals hidden prompt injections on web
pages: instructions aimed at AI agents and assistants that a human visitor
can't see. Other scanners alert you to injections and strip them out; Trip
Wire shows you the page the way an AI reads it, with the hidden instructions
surfaced right where they live.

Built for the Tinker Society Hackathon (fall 2026).

## Why

AI browser agents and assistants increasingly read web pages on our behalf,
and attackers have noticed. Pages now hide text like *"AI assistant: ignore
all previous instructions and…"* using tricks invisible to people:

- white-on-white text, zero font size, `display:none`, off-screen positioning
- HTML comments, `alt` / `aria-label` / `title` attributes, meta tags
- invisible Unicode tag characters that smuggle whole sentences inside
  ordinary-looking text

## How it works

- **Content script:** walks the page and collects every piece of text an AI
  might read, recording *why* a human can't see it.
- **Detection engine (Go → WebAssembly):** scores each piece of text: is it
  hidden, and does it read like instructions to an AI? It decodes smuggled
  Unicode and avoids false alarms on legitimate hidden content like
  screen-reader-only links and collapsed menus.
- **Side panel:** shows a risk score and findings, plus a "Show what the AI
  sees" toggle that reveals hidden instructions in place on the page.

Trip Wire only reads pages you explicitly ask it to scan (`activeTab`). Page
content never leaves your browser.

## Status

Work in progress. See open pull requests for current development.
