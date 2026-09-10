---
layout: default
lang: en
title: 1337 Security Workbench
description: 1337 Security Workbench by Fuzzy Technologies — open security workstation and model-agnostic runtime for AI security agents.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Site navigation">
<div class="language-switch" aria-label="Language">
<a class="lang-button active" href="{{ '/' | relative_url }}" aria-current="page">EN</a>
<a class="lang-button" href="{{ '/ru/' | relative_url }}">RU</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.github.io/" aria-label="Fuzzy Technologies">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid">
<div class="hero-primary">
<p class="eyebrow">Open security workstation · Model-agnostic runtime for AI security agents</p>
<p class="hero-hook">Your tools find things.<br><strong>1337 keeps the security state</strong></p>
<span class="status">Early pre-alpha · Apache-2.0 Community core · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>An open security workspace for penetration testers, security engineers, researchers, and security teams. 1337 turns output from specialist tools into attributable evidence and durable security state for reachability and attack-path analysis.</p>
<blockquote class="hero-quote"><strong>Models reason. 1337 keeps state, governs execution, and preserves evidence</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">Roadmap</a>
</div>
</div>
</section>

<section class="content-section">
<h2>Scanning is only the start</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Tool silos</span>
<h3>Scanner output is not security state</h3>
<p>Nmap knows ports. Nuclei knows template matches. A browser knows the current session. A report is a point-in-time snapshot. The operator still has to connect the pieces.</p>
</section>

<section class="card">
<span class="card-label">AI needs durable context</span>
<h3>Reasoning is not memory</h3>
<p>An AI model can analyze an assessment, but a chat session is not an asset model, an authorization boundary, an evidence store, or an attack graph.</p>
</section>

<section class="card">
<span class="card-label">Prioritization</span>
<h3>Severity does not show the path</h3>
<p>A high-severity finding does not tell you whether an attacker can reach a critical asset, how exposures chain together, or which control breaks that chain.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>From tool output to security state</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 evidence flow">
<pre><code>Tool / Scanner
      ↓
   Evidence
      ↓
Security Objects
      ↓
   Findings
      ↓
 Reachability
      ↓
 Attack Paths
      ↓
 Next Decision</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>1337 does not replace your toolbox. It provides the state and evidence layer around it</strong></p>
<p>Specialist tools keep doing what they do best. 1337 is designed to preserve their results as attributable evidence, connect them to durable security objects, and make that state reusable by people, automation, and future AI agents.</p>
<p class="workbench-note">The value starts where a tool normally stops: after output exists, but before evidence, reachability, security context, and the next decision have been connected.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>One core, different workflows</h2>
<div class="grid">
<section class="card">
<span class="card-label">Security practitioners</span>
<h3>Penetration testers &amp; security engineers</h3>
<p>Keep tool output, evidence, scope, and investigation context together so meaningful attack paths do not have to be reconstructed from terminal history and notes.</p>
</section>

<section class="card">
<span class="card-label">AI &amp; automation</span>
<h3>AI security engineering</h3>
<p>Connect the AI model your organization trusts to the same structured security state and typed capabilities. Scope, execution policy, and evidence stay outside model discretion, so the model can change without redesigning the workflow.</p>
<p class="card-hook">Bring your model. 1337 brings the cyber workspace</p>
</section>

<section class="card">
<span class="card-label">Security operations</span>
<h3>Security teams</h3>
<p>Maintain context across findings, identities, controls, and assets so teams can focus on reachable risk, attack paths, and the remediation that removes the most exposure.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Core architecture</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Security Object Model</h3><p>A shared model for assets, services, endpoints, identities, controls, evidence, findings, reachability, and attack paths.</p></section>
<section class="architecture-card"><h3>Capability Fabric</h3><p>A typed layer for invoking security capabilities without binding a workflow to one scanner, tool, or AI provider.</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Explicit authorization, target scope, impact, and execution constraints that stay outside model discretion.</p></section>
<section class="architecture-card"><h3>Executor Runtime</h3><p>Controlled execution for tools and native capabilities instead of unrestricted shell access.</p></section>
<section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>Material conclusions remain traceable to source, scope, time, tool, executor, and supporting artifacts.</p></section>
<section class="architecture-card"><h3>Reachability &amp; Attack Graph</h3><p>Correlate exposures, identities, and controls into attack paths to critical assets and outcomes.</p></section>
</div>
<p class="invariant"><strong>The model is replaceable. The security state is not</strong></p>
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
<p><strong>Repository → CI Job → Runner → Registry → Deployment → Production</strong></p>
</section>
</div>

<blockquote><strong>Which attack paths are actually reachable, what evidence supports them, and which control breaks the chain?</strong></blockquote>
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
<li>interactive shell and workspace UX</li>
<li>production scanner adapters</li>
<li>findings and reachability workflows</li>
<li>attack graph UX</li>
<li>AI-agent interfaces</li>
<li>enterprise capabilities</li>
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
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0008-ai-native-cyber-execution-platform.md">AI-native platform</a>
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
