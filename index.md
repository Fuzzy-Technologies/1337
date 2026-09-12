---
layout: default
lang: en
title: 1337 Security Workbench
description: 1337 Security Workbench by Fuzzy Technologies — an open, local-first security workbench for penetration testing, investigations, and engineering analysis, built around a live Security Object Model and modular tooling.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Site navigation">
<div class="language-switch" aria-label="Language">
<a class="lang-button active" href="{{ '/' | relative_url }}" aria-current="page">EN</a>
<a class="lang-button" href="{{ '/ru/' | relative_url }}">RU</a>
<a class="lang-button" href="{{ '/zh-cn/' | relative_url }}">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.github.io/" aria-label="Fuzzy Technologies">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid">
<div class="hero-primary">
<p class="eyebrow">Open security workbench · Live Security Object Model · Modular tooling</p>
<p class="hero-hook">Explore the system.<br><strong>Build the model as you work</strong></p>
<span class="status">Early pre-alpha · Apache-2.0 · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>A fast, local-first workbench for penetration testing, security investigations, and engineering analysis. Built-in discovery creates the initial model; native and external tools continuously enrich it with observations, evidence, findings, relationships, reachability, and attack paths.</p>
<blockquote class="hero-quote"><strong>Models reason. 1337 keeps state, governs execution, and preserves evidence</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">Roadmap</a>
</div>
</div>
</section>

<section class="content-section">
<h2>One live model instead of disconnected tool output</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Built-in discovery</span>
<h3>Start with a useful baseline</h3>
<p>1337 can discover targets, hosts, services, endpoints, technologies, and relationships on its own. As additional tools and data sources are connected, the model is refined and expanded.</p>
</section>

<section class="card">
<span class="card-label">Shared state</span>
<h3>Every tool contributes to the same model</h3>
<p>Nmap, Nuclei, browsers, Kali toolsets, imported artifacts, and external systems add attributable observations to one model instead of leaving behind disconnected reports.</p>
</section>

<section class="card">
<span class="card-label">Live workbench</span>
<h3>Long-running jobs do not block the operator</h3>
<p>Commands run on the left while the selected model view updates on the right in real time: objects, evidence, findings, attack paths, or timelines.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>From initial discovery to a durable Security Object Model</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 data flow">
<pre><code>Built-in discovery
      ↓
Security Objects
      ↑
 Tools / Sources
      ↓
Observations + Evidence
      ↓
Findings + Relationships
      ↓
Reachability / Attack Paths</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>Built-in discovery creates the baseline. Your tools enrich it</strong></p>
<p>Tools are part of the workbench, not bolted on. Built-in checks, familiar command-line tools, browsers, load generators, external scanners, and integrations all contribute to one workspace instead of producing separate data silos.</p>
<p class="workbench-note">The core runs locally and requires no mandatory endpoint agents. Heavy scanners, Kali toolsets, browser runtimes, search indexes, and vendor connectors are enabled only when needed.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>One model, four initial workflow lenses</h2>
<div class="grid">
<section class="card">
<span class="card-label">Pentest</span>
<h3>Attack surface and attack paths</h3>
<p>Discovery, findings, credentials, footholds, pivots, reachability, attack paths, and controlled validation — with direct access to familiar tools.</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>Evidence and attacker reconstruction</h3>
<p>Provenance, artifacts, IOCs, timelines, relationships, confidence, and evidence-backed reconstruction. Every material conclusion remains traceable to source evidence.</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>From source to runtime</h3>
<p>Source code, dependencies, SBOMs, images, deployments, APIs, runtime relationships, findings, and reproducible security gates in one model.</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>Attack, detection, control, retest</h3>
<p>Link authorized offensive actions to telemetry, detections, defensive controls, and retest results in the same model.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Core architecture</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Security Object Model</h3><p>A shared model for targets, assets, services, endpoints, identities, evidence, findings, relationships, reachability, and attack paths.</p></section>
<section class="architecture-card"><h3>Built-in Discovery (Native Discovery)</h3><p>Builds the initial black-box model without requiring external scanners or integrations.</p></section>
<section class="architecture-card"><h3>Modular Tooling</h3><p>Built-in engines and replaceable external providers expose capabilities without tying the workbench to one scanner or distribution.</p></section>
<section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>Observations and conclusions remain traceable to source, authorized scope, time, tool, executor, and supporting artifacts.</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Explicit authorization and impact constraints govern execution without becoming the product itself.</p></section>
<section class="architecture-card"><h3>Lenses &amp; Interfaces</h3><p>TUI, Web, API, SDK, MCP, CI, and AI use the same underlying state through workflow-focused views.</p></section>
</div>
<p class="invariant"><strong>One Security Object Model · Multiple lenses · Any suitable tool</strong></p>
</section>

<section class="content-section">
<h2>M4 showcase: reproducible attack paths</h2>
<div class="roadmap-panel">
<div class="roadmap-heading">
<span class="status roadmap-status">M4 roadmap · reproducible lab</span>
<a href="https://github.com/Fuzzy-Technologies/1337/issues/115">Showcase specification #115 →</a>
</div>

<p>M4 is planned as a repository-owned Docker Compose lab with three attack-path scenarios over the same 1337 model. Users should be able to run the lab locally, assess it with authorized tools, inspect the evidence, validate an attack path, apply a security control, and recompute the graph.</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">Business-critical path</span>
<p><strong>Internet → Customer Portal → Identity → Billing API → Critical Business Action</strong></p>
</section>

<section class="case-card">
<span class="card-label">Identity &amp; privilege</span>
<p><strong>Internet → Support Portal → User Identity → SSO/IAM → Admin Console</strong></p>
</section>

<section class="case-card">
<span class="card-label">Software supply chain</span>
<p><strong>Repository → CI Job → Runner → Artifact Registry → Deployment → Production</strong></p>
</section>
</div>

<blockquote><strong>Which paths to critical assets are actually reachable, what evidence supports them, and which security control breaks the chain?</strong></blockquote>
<p class="quiet">M4 is roadmap work and is not part of v0.1.8. The goal is a reproducible Docker Compose lab, not a prerecorded demo.</p>
<p class="showcase-hook"><strong>Run the lab · reproduce the issue · validate the path · verify the fix</strong></p>
</div>
</section>

<section class="content-section">
<h2>What works today</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">Available in v0.1.8</span>
<h3>Working pre-alpha engineering foundation</h3>
<ul>
<li>open core under Apache-2.0</li>
<li>installable 1337 and 1337-dev commands</li>
<li>Command Registry foundations</li>
<li>repository-owned isolated test lab</li>
<li>pytest-native functional-test foundations</li>
<li>public versioned contracts and architecture documentation</li>
<li>deterministic multi-platform quality gates</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">Next milestones</span>
<h3>In development</h3>
<ul>
<li>live split-pane terminal workbench</li>
<li>built-in discovery and a minimal Security Object Model</li>
<li>pluggable scanners and tools, plus Quick Scan</li>
<li>Pentest, DFIR, DevSecOps, and Purple Team workflow lenses</li>
<li>evidence, reachability analysis, and attack paths</li>
<li>API/SDK/MCP and vendor integrations</li>
</ul>
</section>
</div>
<p class="section-hook">A capability is considered implemented only when it is backed by code, tests, and public contracts. Everything else remains explicitly roadmap work</p>
</section>

<section class="content-section">
<h2>Project resources</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Architecture vision</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">AI-agent integration</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">ADR 0010: Workbench architecture</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">Security policy</a>
</div>
</section>

<section class="content-section">
<h2>Responsible use</h2>
<p>1337 is intended for defensive security engineering, authorized penetration testing, investigations, training, research, CTF/lab environments, and systems you own or are explicitly authorized to test.</p>
<p>Do not use the project to scan, probe, exploit, or disrupt third-party systems without authorization.</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">Technologies · Knowledge · Science</span>
</footer>
