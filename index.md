---
layout: default
lang: en
title: 1337 Security Workbench
description: 1337 Security Workbench by Fuzzy Technologies — an open, local-first security workbench for penetration testing, investigations, and security engineering, built around a live Security Object Model and modular tooling.
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
<figure class="hero-primary">
<img class="hero-image" src="{{ '/static/images/1337-logo.png' | relative_url }}" alt="1337 project artwork with Maria at a security workbench" width="1774" height="887" decoding="async" fetchpriority="high" />
<figcaption class="hero-caption">
<p class="eyebrow">Open security workbench · Live Security Object Model · Modular tooling</p>
<p class="hero-hook">Explore the system.<br><strong>Build the model as you work</strong></p>
<span class="status">Early Community product · Apache-2.0 · v0.3.0</span>
</figcaption>
</figure>

<div class="hero-secondary">
<p>Run explicitly approved checks, retain their original evidence, and reopen a portable Security Object Model after execution ends. Start with an owned local demo or a reproducible Git metadata exposure Finding using only 1337 and CPython. Optional Nmap, Nuclei and Trivy workflows add selected provider observations.</p>
<blockquote class="hero-quote"><strong>Models reason. 1337 keeps state, governs execution, and preserves evidence</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0">Release v0.3.0</a>
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
<p>Explicitly selected HTTP endpoints produce status-only Host, Port, Service and Endpoint objects. The owned demo makes three bounded loopback requests; discovery alone creates no vulnerability Finding and does not establish a clean target.</p>
</section>

<section class="card">
<span class="card-label">Shared state</span>
<h3>Every tool contributes to the same model</h3>
<p>Selected first-party checks, optional Nmap/Nuclei/Trivy providers and supported artifact imports retain attributable observations in the same saved model. Reopen verified evidence and export JSON, SARIF, HTML or JUnit offline.</p>
</section>

<section class="card">
<span class="card-label">Human, agent and CI</span>
<h3>Share the same execution and evidence contracts</h3>
<p>Use the CLI, interactive shell or copyable CI recipes with explicit scope, policy, approval and finite limits. Command events and saved-model inspection are available; the complete concurrent split-pane workbench remains roadmap work.</p>
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
Reachability / Attack Paths (roadmap)</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>Built-in discovery creates the baseline. Your tools enrich it</strong></p>
<p>Selected built-in checks and optional tool providers contribute to one workspace instead of producing separate data silos. Broader browser workflows, load generators and vendor integrations remain extension direction; the version-pinned recipes state each implemented operation and its prerequisites.</p>
<p class="workbench-note">The core runs locally and requires no mandatory endpoint agents. Heavy scanners, Kali toolsets, browser runtimes, search indexes, and vendor connectors are enabled only when needed.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>Design direction: one model, four workflow lenses</h2>
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
<h2>Core architecture and extension direction</h2>
<p>The CLI, foreground shell and documented SDK surfaces expose current operations. The wider Web/MCP interfaces, full concurrent TUI and advanced attack-path workflows described by this architecture remain roadmap work.</p>
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
<p class="quiet">The complete M4 showcase remains roadmap work beyond v0.3.0. The repository already includes an isolated attack-path mini lab.</p>
<p class="showcase-hook"><strong>Run the lab · reproduce the issue · validate the path · verify the fix</strong></p>
</div>
</section>

<section class="content-section">
<h2>What works today</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">Available in v0.3.0</span>
<h3>Useful installed workflows with retained evidence</h3>
<ul>
<li>Apache-2.0 open-source core</li>
<li>installable 1337 and 1337-dev commands</li>
<li>interactive shell, fuzzy completion, palette and history</li>
<li>local doctor and read-only component inspection</li>
<li>owned loopback demo with approval preview, three acquisitions and confirmed target teardown</li>
<li>core-only Git HEAD exposure recipe with one LOW Finding and a fixed negative control</li>
<li>durable model, evidence verification, offline reopen and JSON/SARIF/HTML/JUnit exports</li>
<li>selected Nmap/Nuclei checks and offline native Trivy image/configuration workflows</li>
<li>read-only saved image SBOM inspection; license compliance and runtime reachability remain unknown</li>
<li>repository-owned isolated test lab</li>
<li>public versioned contracts and architecture documentation</li>
</ul>
<p>Start with CPython 3.11 or newer; the base wheel has no mandatory runtime dependencies:</p>
<pre><code>python -m pip install 1337==0.3.0
1337 --version
1337 doctor
mkdir artifacts
1337 demo local artifacts/first-run --json</code></pre>
<p>The preview returns exit 3 and <code>approval_required</code> without starting a target. Read the exact plan, then follow the <a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md">version-pinned quickstart</a> to approve that invocation, run it and inspect its saved evidence. Optional tools are not installed or authorized implicitly.</p>
<p>For an attributable Finding, use the complete <a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/OWNED_GIT_HEAD_RECIPE.md">owned Git HEAD recipe</a>. It includes the standalone fixture, explicit scope/policy, separately confirmed positive/fixed plans and offline reports; no external scanner or model API is required.</p>
</section>

<section class="proof-card">
<span class="card-label">Next milestones</span>
<h3>In development</h3>
<ul>
<li>live split-pane terminal workbench</li>
<li>broader authenticated application checks and provider coverage</li>
<li>complete Pentest, DFIR, DevSecOps and Purple Team workflow lenses</li>
<li>evidence-backed live reachability and the M4 attack-path showcase</li>
<li>broader SBOM semantics, license policy and runtime correlation</li>
<li>general MCP service and vendor integrations</li>
</ul>
</section>
</div>
<p class="section-hook">A capability is considered implemented only when it is backed by code, tests, and public contracts. Everything else remains explicitly roadmap work</p>
</section>

<section class="content-section">
<h2>Project resources</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md">Try v0.3.0</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md">AI-agent quickstart</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/CI_QUICKSTART.md">CI quickstart</a>
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
