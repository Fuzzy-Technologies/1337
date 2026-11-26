---
layout: default
lang: zh-CN
title: 1337 Security Workbench
description: Fuzzy Technologies 打造的开源、本地优先安全工作台。执行经过授权的检查，保留原始证据，并离线复核结果。
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="站点导航">
<div class="language-switch" aria-label="语言">
<a class="lang-button" href="{{ '/' | relative_url }}">EN</a>
<a class="lang-button" href="{{ '/ru/' | relative_url }}">RU</a>
<a class="lang-button active" href="{{ '/zh-cn/' | relative_url }}" aria-current="page">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.com/zh-cn/">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid" aria-labelledby="intro">
<div class="hero-secondary">
<p class="eyebrow">开源安全工作台</p>
<h2 class="hero-hook" id="intro">执行安全检查。<br><strong>保留原始证据。</strong></h2>
<p>1337 将经过授权的检查、发现项和原始证据保存在同一个本地工作空间。即使目标系统已离线，你也可以重新打开结果、核对每项发现的依据，并与同事分享报告。</p>
<div class="links hero-actions">
<a class="primary-action" href="#get-started">试用本地演示</a>
<a href="#roadmap">查看路线图</a>
</div>
</div>
<figure class="hero-primary">
<img class="hero-image" src="{{ '/static/images/1337-logo.png' | relative_url }}" alt="插画中的 Maria 坐在 1337 安全工作台前" width="1774" height="887" decoding="async" fetchpriority="high" />
</figure>
</section>

<section class="content-section">
<h2 id="workflow">从安全检查到报告</h2>
<div class="grid">
<article class="card">
<h3>设定检查范围</h3>
<p>选择已获授权的系统和检查项。执行策略规定哪些操作可以执行、哪些需要确认。</p>
</article>
<article class="card">
<h3>构建系统模型</h3>
<p>安全对象模型将资产、服务、端点和发现项与对应的原始观测结果及证据关联起来。</p>
</article>
<article class="card">
<h3>离线复核</h3>
<p>打开保存的工作空间，追溯发现项的原始依据，并导出报告，无需再次访问目标系统。</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="community">Community v0.3.0 已发布</h2>
<p>你可以先运行完全在本机执行的演示。社区版提供交互式命令行、基础 HTTP 检查和内置 Web 检查，也支持选用 Nmap、Nuclei 和 Trivy 的工作流程。保存工作空间后可导出 HTML、JSON、SARIF 或 JUnit 报告。CI 可以执行经过授权的检查，并按预设规则判断结果。</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0">查看社区版发布说明 →</a></p>
</section>

<section class="content-section">
<h2 id="development">开发分支已实现的功能</h2>
<p>0.4 开发分支加入了分步评估流程和更易阅读的离线 HTML 报告。指定的 CVE、CWE 和 EPSS 记录可为发现项补充背景信息。FuzzyRoutines 提供 CVSS 分数的五级解读，报告同时保留原始分数。</p>
<p>开发分支扩展了内置 Web 检查，能够离线导入 CycloneDX 软件物料清单（SBOM）、SARIF 报告和 syslog 日志，并可基于已保存的工作空间分析选定路径、比较其状态。</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/CHANGELOG.md">查看 develop 分支更新记录 →</a></p>
</section>

<section class="content-section">
<h2 id="use-cases">适用场景</h2>
<div class="grid">
<article class="card">
<h3>应用安全与渗透测试</h3>
<p>评估获准测试的服务，将开发人员复核问题所需的证据交给他们。</p>
</article>
<article class="card">
<h3>DevSecOps</h3>
<p>保留 CI 报告，随时查阅作出发布决策时依据的检查结果。</p>
</article>
<article class="card">
<h3>事件调查</h3>
<p>复核已保存的资料，将原始数据随工作空间一起交给其他分析人员。</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="ai-agents">面向工程师、CI 和 AI 智能体</h2>
<p>工程师、CI 流水线和能使用终端的 AI 智能体可以使用同一套工作空间。智能体可以提出计划并解释结果。1337 根据范围和审批规则管控执行，并保留操作记录。本地流程无需开通模型服务账号。</p>
</section>

<section class="content-section">
<h2 id="roadmap">接下来的开发方向</h2>
<div class="architecture-grid">
<article class="architecture-card">
<h3>Web Scanner NG 与可达性分析</h3>
<p>扩展内置的 Web 应用和 API 检查，用图谱展示资产之间的可达性与潜在攻击路径，并追溯对应证据。</p>
</article>
<article class="architecture-card">
<h3>交互式分析</h3>
<p>提供多面板终端和 Web 界面，方便查看发现项、比较评估结果，并理解风险排序的依据。</p>
</article>
<article class="architecture-card">
<h3>事件调查与紫队协作</h3>
<p>在同一个工作空间中梳理事件时间线，并为分析人员和防御团队提供关联观测、检测结果与证据的视图。</p>
</article>
<article class="architecture-card">
<h3>工具集成与 AI</h3>
<p>提供 API、SDK、CI 集成和受策略约束的 MCP 接入，支持自主选择 AI 模型及服务提供商。</p>
</article>
</div>
<p><a href="https://github.com/Fuzzy-Technologies/1337/milestones">查看公开开发路线图 →</a></p>
</section>

<section class="content-section">
<h2 id="get-started">在本机试用 1337</h2>
<p>社区版快速入门会带你运行独立的本地演示、保存证据，再离线打开报告。以下指南为英文。</p>
<div class="links">
<a class="primary-action" href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md">快速入门</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md">AI 智能体指南</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/CI_QUICKSTART.md">CI 指南</a>
</div>
</section>

<section class="content-section">
<h2 id="project">开源社区核心</h2>
<p>Fuzzy Technologies 公开开发 1337。社区版核心采用 Apache 2.0 许可。</p>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub 源代码</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/VISION.md">项目愿景</a>
</div>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
</footer>
