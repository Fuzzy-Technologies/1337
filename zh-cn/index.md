---
layout: default
lang: zh-CN
title: 1337 Security Workbench
description: Fuzzy Technologies 的 1337 Security Workbench —— 本地优先的开放式网络安全工作台，围绕实时安全对象模型与模块化安全工具构建。
keywords: 1337 Security Workbench, 网络安全, 安全工作台, AI 安全, 网络安全 AI 智能体, 渗透测试, 安全自动化, 攻击图, 攻击路径, 可达性分析, 证据来源追踪, Fuzzy Technologies
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="站点导航">
<div class="language-switch" aria-label="语言">
<a class="lang-button" href="{{ '/' | relative_url }}">EN</a>
<a class="lang-button" href="{{ '/ru/' | relative_url }}">RU</a>
<a class="lang-button active" href="{{ '/zh-cn/' | relative_url }}" aria-current="page">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.github.io/" aria-label="Fuzzy Technologies">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid">
<div class="hero-primary">
<p class="eyebrow">开放式网络安全工作台 · 实时安全对象模型 · 模块化安全工具</p>
<p class="hero-hook">发现系统。<br><strong>在工作过程中持续构建模型</strong></p>
<span class="status">早期 pre-alpha · Apache-2.0 Community core · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>面向实践型安全工作的快速、本地优先工作台。原生发现先建立初始模型；内置与可插拔工具随后用证据、发现项、关系、可达性和攻击路径持续丰富同一状态。</p>
<blockquote class="hero-quote"><strong>模型负责推理。1337 保存状态、管控执行并保存证据</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">路线图</a>
</div>
</div>
</section>

<section class="content-section">
<h2>一个实时模型，而不是一堆孤立输出</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">原生发现</span>
<h3>无需先安装大型外部工具即可开始建模</h3>
<p>1337 先发现基础目标、主机、服务、端点、技术与关系，再随着更多传感器接入不断扩展模型。</p>
</section>

<section class="card">
<span class="card-label">共享状态</span>
<h3>所有传感器丰富同一个模型</h3>
<p>Nmap、Nuclei、浏览器、Kali 工具包、导入工件与厂商集成都贡献可追溯观察，而不是形成彼此割裂的结果孤岛。</p>
</section>

<section class="card">
<span class="card-label">实时 Workbench</span>
<h3>长时间任务不会阻塞操作人员</h3>
<p>左侧执行命令，右侧按当前 lens 增量更新相关模型切片：对象、证据、发现项、路径或时间线。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>从发现到持久的 Security Object Model</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 证据流">
<pre><code>原生发现
      ↓
安全对象
      ↑
工具 / 传感器
      ↓
观察 + 证据
      ↓
发现项 + 关系
      ↓
可达性 / 攻击路径</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>原生发现建立模型，专业工具继续丰富它</strong></p>
<p>工具能力是一等公民：原生能力、熟悉的外部 CLI、浏览器、负载引擎、厂商扫描器和未来集成都向同一个 workspace 提供数据。</p>
<p class="workbench-note">Core 保持本地优先与 agentless-first。大型扫描器、Kali 工具包、浏览器、搜索索引和厂商连接器按需启用。</p>
</div>
</div>
</section>

<section class="content-section">
<h2>一个模型，四个初始 lenses</h2>
<div class="grid">
<section class="card">
<span class="card-label">Pentest</span>
<h3>攻击面与下一步可达路径</h3>
<p>聚焦侦察、发现项、凭据、横向移动、可达性、攻击路径与受控验证，同时保留对熟悉工具的直接访问。</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>证据与实际攻击者路径</h3>
<p>聚焦来源追踪、实体、IOC、时间线、置信度与基于证据的事件重建，不建立独立的取证真相库。</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>从代码到制品再到运行时</h3>
<p>聚焦源码、依赖、SBOM、镜像、部署、API、运行时关系、发现项以及确定性的安全门禁。</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>动作、检测、控制与复测</h3>
<p>使用同一状态连接授权的 offensive 动作、telemetry、detections、防护控制与验证前后的变化。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>核心架构</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Security Object Model</h3><p>面向目标、资产、服务、端点、身份、证据、发现项、关系、可达性与路径的持久核心。</p></section>
<section class="architecture-card"><h3>Native Discovery</h3><p>无需强制安装外部扫描器或集成，即可先建立初始 black-box 模型。</p></section>
<section class="architecture-card"><h3>模块化工具</h3><p>原生引擎与可替换外部 providers 提供能力，不强制绑定单一扫描器或发行版。</p></section>
<section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>观察与结论始终可追溯到来源、scope、时间、工具、executor 与支撑工件。</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>授权范围与 impact 约束负责管控动作，但它们不是产品本身。</p></section>
<section class="architecture-card"><h3>Lenses &amp; Interfaces</h3><p>TUI、Web、API、SDK、MCP、CI 与 AI 通过不同工作视图使用同一状态。</p></section>
</div>
<p class="invariant"><strong>一个 Security Object Model · 多个 lenses · 任意合适工具</strong></p>
</section>

<section class="content-section">
<h2>M4 展示：可复现的攻击路径</h2>
<div class="roadmap-panel">
<div class="roadmap-heading">
<span class="status roadmap-status">M4 路线图 · 可复现实验环境</span>
<a href="https://github.com/Fuzzy-Technologies/1337/issues/115">展示规范 #115 →</a>
</div>

<p>M4 计划提供一个由项目仓库维护的 Docker Compose 实验环境，在同一份 1337 安全状态之上复现三类攻击路径。用户应能够在本地启动环境、使用允许的工具进行扫描、查看证据、验证路径、应用安全控制措施，并重新计算攻击图。</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">业务影响</span>
<p><strong>Internet → 客户门户 → 身份 → Billing API → 业务事件</strong></p>
</section>

<section class="case-card">
<span class="card-label">身份与权限</span>
<p><strong>Internet → 支持门户 → 用户身份 → SSO/IAM → 管理控制台</strong></p>
</section>

<section class="case-card">
<span class="card-label">软件供应链</span>
<p><strong>代码仓库 → CI Job → Runner → 制品仓库 → Deployment → Production</strong></p>
</section>
</div>

<blockquote><strong>哪些通往关键资产的攻击路径确实可达？依据是什么？哪项安全控制措施能够切断这条链路？</strong></blockquote>
<p class="quiet">M4 仍属于路线图内容，并不包含在 v0.1.8 中。目标是一个可复现的 Compose 实验环境，而不是预先录制的演示。</p>
<p class="showcase-hook"><strong>启动环境 · 复现发现项 · 验证攻击路径 · 验证修复效果</strong></p>
</div>
</section>

<section class="content-section">
<h2>当前已经可用的内容</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">v0.1.8 已提供</span>
<h3>可复现的 pre-alpha 基础</h3>
<ul>
<li>Apache-2.0 Community core</li>
<li>可安装的 1337 / 1337-dev bootstrap 命令</li>
<li>Command Registry 基础</li>
<li>项目仓库自带的隔离式合成测试环境</li>
<li>基于 pytest 的功能测试基础</li>
<li>公开、版本化的接口契约 (contracts) 与架构文档</li>
<li>确定性的多平台质量门禁 (quality gates)</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">v0.1.8 之后的路线图</span>
<h3>规划中的产品能力</h3>
<ul>
<li>实时 split-pane terminal workbench</li>
<li>native discovery 与最小 Security Object Model</li>
<li>模块化 scanner/tool providers 与 Quick Scan</li>
<li>Pentest / DFIR / DevSecOps / Purple lenses</li>
<li>evidence、reachability 与 attack-path workflows</li>
<li>API/SDK/MCP 与 vendor integrations</li>
</ul>
</section>
</div>
<p class="section-hook">当前能力以代码、测试和公开契约为准；尚未实现的能力始终明确标注为路线图内容</p>
</section>

<section class="content-section">
<h2>项目资源</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">架构愿景</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">AI 智能体架构</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">Live Workbench architecture</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">安全策略</a>
</div>
</section>

<section class="content-section">
<h2>负责任地使用</h2>
<p>1337 用于防御性安全工程、经授权的安全评估、培训、研究、CTF / 实验环境，以及你拥有或已获得明确授权进行测试的系统。</p>
<p>未经授权，不得使用本项目扫描、探测、利用或干扰第三方系统。</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">技术 · 知识 · 科学</span>
</footer>
