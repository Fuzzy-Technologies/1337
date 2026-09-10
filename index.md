---
layout: default
lang: en
title: 1337 Security Workbench
description: 1337 Security Workbench by Fuzzy Technologies — open security workstation and model-neutral cybersecurity runtime for humans and AI agents.
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
    <p class="eyebrow">Open security workstation · Model-neutral cyber runtime</p>
    <p class="hero-hook">Your tools find things.<br><strong>1337 keeps the security state.</strong></p>
    <span class="status">Early pre-alpha · Apache-2.0 Community core · v0.1.8</span>
  </div>
  <div class="hero-secondary">
    <p>An open security workstation for hackers, security engineers, researchers, and security teams — built to turn specialist-tool output into attributable evidence and durable security state for reachability and attack-path reasoning.</p>
    <blockquote class="hero-quote"><strong>Models reason. 1337 remembers, governs, executes and proves.</strong></blockquote>
    <div class="links hero-actions">
      <a href="https://github.com/Fuzzy-Technologies/1337">GitHub repository</a>
      <a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
      <a href="https://github.com/Fuzzy-Technologies/1337/milestones">Roadmap</a>
    </div>
  </div>
</section>

<section class="content-section">
  <h2>The scan is not the hard part</h2>
  <div class="grid problem-grid">
    <section class="card">
      <span class="card-label">Fragmented tools</span>
      <h3>Output is not security state</h3>
      <p>Nmap knows ports. Nuclei knows templates. Browsers know sessions. Reports know yesterday. The operator still has to reconstruct the picture.</p>
    </section>
    <section class="card">
      <span class="card-label">AI needs durable context</span>
      <h3>Reasoning is not memory</h3>
      <p>A capable model can analyze security data. A chat window is still not an asset model, authorization boundary, evidence store, or attack graph.</p>
    </section>
    <section class="card">
      <span class="card-label">Prioritization</span>
      <h3>Severity is not a path</h3>
      <p>A vulnerability count does not tell you what is actually reachable, what chains together, or which remediation breaks the route to what matters.</p>
    </section>
  </div>
</section>

<section class="content-section">
  <h2>1337 begins after the tool runs</h2>
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
      <p class="section-hook"><strong>1337 does not replace your toolbox. It is the workbench around it.</strong></p>
      <p>Specialist tools remain specialist tools. 1337 is designed to preserve their output as attributable evidence, connect it to durable security objects, and make the resulting state reusable by humans, automation, and future AI operators.</p>
      <p class="workbench-note">The useful boundary begins where a tool normally stops: after the output exists, but before the security state, reachability, provenance, and next decision have been connected.</p>
    </div>
  </div>
</section>

<section class="content-section">
  <h2>One Core, several operators</h2>
  <div class="grid">
    <section class="card">
      <span class="card-label">Hands on keyboard</span>
      <h3>Hackers &amp; security engineers</h3>
      <p>Connect specialist tools, preserve evidence and context, and investigate meaningful attack paths instead of rebuilding the assessment from terminal history.</p>
    </section>
    <section class="card">
      <span class="card-label">Bring your model</span>
      <h3>AI security builders</h3>
      <p>Use structured security objects and typed capabilities between replaceable AI reasoning and raw security tooling, without making one model provider the architecture.</p>
      <p class="card-hook">Bring your model. 1337 brings the cyber workspace.</p>
    </section>
    <section class="card">
      <span class="card-label">Continuous context</span>
      <h3>Security teams</h3>
      <p>Build toward a governed view of what changed, what became reachable, which paths matter, and which remediation has the greatest effect.</p>
    </section>
  </div>
</section>

<section class="content-section">
  <h2>Architecture that earns its keep</h2>
  <div class="architecture-grid">
    <section class="architecture-card"><h3>Security Object Model</h3><p>One shared language for assets, services, endpoints, identities, controls, evidence, findings, reachability, and attack paths.</p></section>
    <section class="architecture-card"><h3>Capability Fabric</h3><p>Describe what security operation is needed without hard-wiring the workflow to one scanner or provider.</p></section>
    <section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Keep authorization, impact, and execution boundaries explicit instead of hiding them in prompts or operator memory.</p></section>
    <section class="architecture-card"><h3>Executor Runtime</h3><p>Run tools and native capabilities through controlled execution rather than treating unrestricted shell access as an agent architecture.</p></section>
    <section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>Keep important conclusions traceable to what actually happened: source, scope, time, tool, executor, and supporting artifacts.</p></section>
    <section class="architecture-card"><h3>Reachability &amp; Attack Graph</h3><p>Prioritize routes to meaningful outcomes instead of treating vulnerability counts or severity scores as the whole security picture.</p></section>
  </div>
  <p class="invariant"><strong>The model is replaceable. The security state is not.</strong></p>
</section>

<section class="content-section">
  <h2>Where this is going</h2>
  <div class="roadmap-panel">
    <div class="roadmap-heading">
      <span class="status roadmap-status">M4 roadmap · planned reproducible showcase</span>
      <a href="https://github.com/Fuzzy-Technologies/1337/issues/115">Follow showcase #115 →</a>
    </div>
    <p>The planned public showcase is one repository-owned lab with three evidence-backed cases over the same 1337 security-state model:</p>
    <div class="case-grid">
      <section class="case-card"><span class="card-label">Business impact</span><p><strong>Internet → Customer Portal → Identity → Billing API → Business Event</strong></p></section>
      <section class="case-card"><span class="card-label">Identity / privilege</span><p><strong>Internet → Support Portal → User Identity → SSO/IAM → Admin Console</strong></p></section>
      <section class="case-card"><span class="card-label">Software supply chain</span><p><strong>Repository → CI Job → Runner → Registry → Deployment → Production</strong></p></section>
    </div>
    <blockquote><strong>Can I actually get from here to what matters, why does 1337 believe that, and which control breaks the path?</strong></blockquote>
    <p class="quiet">The M4 showcase is roadmap work, not a claim about v0.1.8. Its design goal is a Compose-based lab that users can run, scan, validate, reset, and independently verify.</p>
    <p class="showcase-hook"><strong>Scan it yourself. Prove the edge. Break the path. Reset the lab. Do it again.</strong></p>
  </div>
</section>

<section class="content-section">
  <h2>Proof, not pitch</h2>
  <div class="proof-grid">
    <section class="proof-card proof-now">
      <span class="card-label">Exists today · v0.1.8</span>
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
      <span class="card-label">Roadmap · not shipped in v0.1.8</span>
      <h3>What still has to be built</h3>
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
  <p class="section-hook">Ambitious architecture is useful only when it becomes reproducible software with explicit contracts, tests, evidence, and honest status.</p>
</section>

<section class="content-section">
  <h2>Explore the project</h2>
  <div class="links">
    <a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Project Vision</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">AI-agent architecture</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0008-ai-native-cyber-execution-platform.md">ADR 0008 · AI-native cyber execution, state &amp; evidence</a>
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
  <span>Technologies · Knowledge · Science</span>
</footer>
