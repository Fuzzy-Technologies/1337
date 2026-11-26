---
layout: default
lang: en
title: 1337 Security Workbench
description: An open, local-first security workbench from Fuzzy Technologies. Run approved checks, keep the evidence, and review the results offline.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Site navigation">
<div class="language-switch" aria-label="Language">
<a class="lang-button active" href="{{ '/' | relative_url }}" aria-current="page">EN</a>
<a class="lang-button" href="{{ '/ru/' | relative_url }}">RU</a>
<a class="lang-button" href="{{ '/zh-cn/' | relative_url }}">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.com/">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid" aria-labelledby="intro">
<div class="hero-secondary">
<p class="eyebrow">Open security workbench</p>
<h2 class="hero-hook" id="intro">Run security checks.<br><strong>Keep the evidence.</strong></h2>
<p>1337 brings approved checks, findings, and original evidence into one local workspace. Reopen the results, see what supports each finding, and share a report even after the target goes offline.</p>
<div class="links hero-actions">
<a class="primary-action" href="#get-started">Try the local demo</a>
<a href="#roadmap">See the roadmap</a>
</div>
</div>
<figure class="hero-primary">
<img class="hero-image" src="{{ '/static/images/1337-logo.png' | relative_url }}" alt="Maria at the 1337 Security Workbench, project artwork" width="1774" height="887" decoding="async" fetchpriority="high" />
</figure>
</section>

<section class="content-section">
<h2 id="ai-agents">One model for engineers, CI, and AI agents</h2>
<div class="model-panel">
<div class="model-summary">
<h3>Security Object Model</h3>
<p>Built-in checks map assets, services, and endpoints. Further checks and connected tools enrich the model with observations and findings. 1337 links findings to the affected objects and the original evidence.</p>
</div>
<div class="grid model-roles">
<article class="card">
<h3>Engineer</h3>
<p>Sets the scope, approves the plan, and verifies conclusions against the evidence.</p>
</article>
<article class="card">
<h3>CI</h3>
<p>Runs approved checks, evaluates results against configured rules, and retains the workspace as a build artifact.</p>
</article>
<article class="card">
<h3>AI agent</h3>
<p>Uses the same CLI to propose checks and help interpret findings in a saved workspace.</p>
</article>
</div>
<p class="model-handoff">If a CI check blocks a release, an AI agent can show which finding matched the rule. An engineer can then open the same model offline, review the original evidence, and decide what to do.</p>
</div>
</section>

<section class="content-section">
<h2 id="workflow">From a check to a report</h2>
<div class="grid">
<article class="card">
<h3>Set the scope</h3>
<p>Choose authorized systems and checks. An execution policy defines the allowed actions and when approval is required.</p>
</article>
<article class="card">
<h3>Build a model</h3>
<p>The Security Object Model connects assets, services, endpoints, and findings to the observations and evidence that support them.</p>
</article>
<article class="card">
<h3>Review offline</h3>
<p>Open the saved workspace, follow a finding to its source, and export a report without contacting the target again.</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="community">Available in Community v0.3.0</h2>
<p>Start with a demo that runs entirely on your machine. The release includes an interactive shell, selected HTTP and native web checks, and optional workflows with Nmap, Nuclei, and Trivy. Save a workspace and export HTML, JSON, SARIF, or JUnit reports. CI can run approved checks and apply explicit rules to their results.</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0">View the Community release →</a></p>
</section>

<section class="content-section">
<h2 id="development">Already in development builds</h2>
<p>The 0.4 development branch adds guided assessment and more readable offline HTML reports. Selected CVE, CWE, and EPSS records add context to a finding. FuzzyRoutines offers a five-level interpretation of the source CVSS score, which stays visible in the report.</p>
<p>The branch expands native web checks and adds offline import of CycloneDX SBOMs, SARIF reports, and syslog records. Early graph tools can analyze selected paths and compare their state from saved workspace data.</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/CHANGELOG.md">Follow changes in develop →</a></p>
</section>

<section class="content-section">
<h2 id="use-cases">Where 1337 fits</h2>
<div class="grid">
<article class="card">
<h3>AppSec and pentesting</h3>
<p>Assess an authorized service and share the evidence a developer needs to review a finding.</p>
</article>
<article class="card">
<h3>DevSecOps</h3>
<p>Keep reports from CI and review the exact results used to make a release decision.</p>
</article>
<article class="card">
<h3>Incident investigation</h3>
<p>Review saved artifacts and keep their source data with the workspace for another analyst.</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="roadmap">What we’re building next</h2>
<div class="architecture-grid">
<article class="architecture-card">
<h3>Web Scanner NG and exposure mapping</h3>
<p>Broader native web and API checks alongside a graph of asset reachability and potential attack paths, with links back to the evidence.</p>
</article>
<article class="architecture-card">
<h3>Interactive analysis</h3>
<p>A split-pane terminal workbench and a web interface for exploring findings, comparing assessments, and explaining risk priorities.</p>
</article>
<article class="architecture-card">
<h3>Incident response and Purple Team</h3>
<p>Investigation timelines and focused views for analysts and defenders to connect observations, detections, and evidence in one workspace.</p>
</article>
<article class="architecture-card">
<h3>Integrations and AI</h3>
<p>APIs, an SDK, CI integrations, and policy-controlled MCP access for AI tools, with a choice of model and provider.</p>
</article>
</div>
<p><a href="https://github.com/Fuzzy-Technologies/1337/milestones">Track the public roadmap →</a></p>
</section>

<section class="content-section">
<h2 id="get-started">Try 1337 on your machine</h2>
<p>The Community quickstart runs a self-contained demo, saves its evidence, and walks you through opening the resulting report offline.</p>
<div class="links">
<a class="primary-action" href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md">Quickstart</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md">AI agent guide</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/CI_QUICKSTART.md">CI guide</a>
</div>
</section>

<section class="content-section">
<h2 id="project">Open Community core</h2>
<p>Fuzzy Technologies develops 1337 in the open. The Community core is available under Apache 2.0.</p>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337">Source on GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/VISION.md">Project vision</a>
</div>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
</footer>
