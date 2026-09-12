---
layout: default
lang: en
title: 1337 Security Workbench
description: 1337 Security Workbench by Fuzzy Technologies — open, local-first security workstation with a live Security Object Model and modular security tooling.
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
<p class="eyebrow">Open security workstation · Live Security Object Model · Modular security tooling</p>
<p class="hero-hook">Discover the system.<br><strong>Build the model while you work</strong></p>
<span class="status">Early pre-alpha · Apache-2.0 Community core · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>A fast, local-first workstation for hands-on security work. Native discovery builds the initial model; built-in and pluggable tools enrich the same state with evidence, findings, relations, reachability, and attack paths.</p>
<blockquote class="hero-quote"><strong>Models reason. 1337 keeps state, governs execution, and preserves evidence</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">Roadmap</a>
</div>
</div>
</section>

<section class="content-section">
<h2>One live model, not a pile of tool output</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Native discovery</span>
<h3>Start useful before optional tools are installed</h3>
<p>1337 is designed to discover the first targets, hosts, services, endpoints, technologies, and relations itself, then extend that picture as more sensors become available.</p>
</section>

<section class="card">
<span class="card-label">Shared state</span>
<h3>Every sensor enriches the same model</h3>
<p>Nmap, Nuclei, browsers, Kali tool packs, imported artifacts, and vendor integrations contribute attributable observations instead of creating disconnected result silos.</p>
</section>

<section class="card">
<span class="card-label">Live workbench</span>
<h3>Long jobs do not block the operator</h3>
<p>Commands run on one side while the relevant model slice updates incrementally on the other: objects, evidence, findings, paths, or timeline according to the selected lens.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>From discovery to a durable Security Object Model</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 evidence flow">
<pre><code>Native discovery
      ↓
Security Objects
      ↑
 Tools / Sensors
      ↓
Observations + Evidence
      ↓
Findings + Relations
      ↓
Reachability / Paths</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>Native discovery starts the model. Your tools make it richer</strong></p>
<p>Tooling is first-class: native capabilities, familiar external CLIs, browsers, workload engines, vendor scanners, and future integrations all feed one durable workspace instead of competing databases.</p>
<p class="workbench-note">Core operation stays local-first and agentless-first. Heavy scanners, Kali packs, browsers, search indexes, and vendor connectors are optional providers loaded when needed.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>One model, four initial lenses</h2>
<div class="grid">
<section class="card">
<span class="card-label">Pentest</span>
<h3>Attack surface and reachable next steps</h3>
<p>Focus on discovery, findings, credentials, pivots, reachability, attack paths, and bounded validation while keeping direct access to familiar tools.</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>Evidence and observed attacker path</h3>
<p>Focus on provenance, entities, IOCs, timelines, confidence, and evidence-backed reconstruction without creating a separate forensic truth store.</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>Code to artifact to runtime</h3>
<p>Focus on source, dependencies, SBOMs, images, deployments, APIs, runtime relationships, findings, and deterministic security gates.</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>Action, detection, control, retest</h3>
<p>Use the same state to compare authorized offensive actions with telemetry, detections, defensive controls, and before/after validation.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Core architecture</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Security Object Model</h3><p>The durable center for targets, assets, services, endpoints, identities, evidence, findings, relations, reachability, and paths.</p></section>
<section class="architecture-card"><h3>Native Discovery</h3><p>Build the initial black-box model before optional scanners and integrations are installed.</p></section>
<section class="architecture-card"><h3>Modular Tooling</h3><p>Native engines and replaceable external providers expose capabilities without making one scanner or distribution mandatory.</p></section>
<section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>Observations and conclusions stay traceable to source, scope, time, tool, executor, and supporting artifacts.</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Authorization and impact constraints govern actions without becoming the product itself.</p></section>
<section class="architecture-card"><h3>Lenses &amp; Interfaces</h3><p>TUI, Web, API, SDK, MCP, CI, and AI consume the same state through focused workflow views.</p></section>
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

<p>M4 is planned as a repository-owned Docker Compose lab with three attack-path scenarios over the same 1337 security state. Users should be able to run the lab locally, scan it with the allowed tools, inspect evidence, validate a path, apply a control, and recompute the graph.</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">Business impact</span>
<p><strong>Internet → Customer Portal → Identity → Billing API → Business Event</strong></p>
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
<p class="quiet">M4 is roadmap work and is not part of v0.1.8. The goal is a reproducible Compose lab, not a prerecorded demo.</p>
<p class="showcase-hook"><strong>Run the lab · reproduce the findings · validate the path · verify the remediation</strong></p>
</div>
</section>

<section class="content-section">
<h2>What works today</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">Available in v0.1.8</span>
<h3>Reproducible pre-alpha foundation</h3>
<ul>
<li>Apache-2.0 Community core</li>
<li>installable 1337 / 1337-dev bootstrap commands</li>
<li>Command Registry foundations</li>
<li>repository-owned isolated synthetic lab</li>
<li>pytest-native functional-test foundations</li>
<li>public versioned contracts and architecture documentation</li>
<li>deterministic multi-platform quality gates</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">Roadmap after v0.1.8</span>
<h3>Planned product capabilities</h3>
<ul>
<li>live split-pane terminal workbench</li>
<li>native discovery and minimal Security Object Model</li>
<li>modular scanner/tool providers and Quick Scan</li>
<li>Pentest / DFIR / DevSecOps / Purple lenses</li>
<li>evidence, reachability and attack-path workflows</li>
<li>API/SDK/MCP and vendor integrations</li>
</ul>
</section>
</div>
<p class="section-hook">Current capability is tied to code, tests, and public contracts; planned capability stays marked as roadmap</p>
</section>

<section class="content-section">
<h2>Project resources</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Architecture vision</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">AI-agent architecture</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">Live Workbench architecture</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">Security Policy</a>
</div>
</section>

<section class="content-section">
<h2>Responsible use</h2>
<p>1337 is intended for defensive security engineering, authorized assessment, training, research, CTF/lab environments, and systems you own or are explicitly authorized to test.</p>
<p>Do not use the project to scan, probe, exploit, or disrupt third-party systems without authorization.</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">Technologies · Knowledge · Science</span>
</footer>
