---
layout: default
lang: zh-CN
title: 1337 Security Workbench
description: Fuzzy Technologies 的 1337 Security Workbench——面向渗透测试、安全调查与安全工程分析的本地优先工作台，以动态安全对象模型（Security Object Model）和可插拔安全工具为核心。
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
<p class="eyebrow">开放式安全工作台 · 动态安全对象模型 · 可插拔安全工具</p>
<p class="hero-hook">分析目标系统。<br><strong>模型随工作过程持续更新</strong></p>
<span class="status">早期 pre-alpha · Apache-2.0 · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>1337 是一套快速、本地优先的安全工作台，面向渗透测试、安全调查和工程化安全分析。内置扫描与发现能力先建立目标系统的初始模型，随后由内置工具和外部工具持续补充观察结果、证据、发现项、关联关系、网络可达性和攻击路径。</p>
<blockquote class="hero-quote"><strong>模型负责推理；1337 负责保存状态、约束执行并留存证据</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">预发布版 v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">开发路线图</a>
</div>
</div>
</section>

<section class="content-section">
<h2>一个动态模型，而不是一堆互不关联的扫描结果</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">内置扫描与发现</span>
<h3>无需依赖外部扫描器也能先建立基础模型</h3>
<p>1337 可先发现目标、主机、服务、端点、技术栈及其关联关系；接入更多工具和数据源后，再持续补充和校验模型。</p>
</section>

<section class="card">
<span class="card-label">统一状态</span>
<h3>所有工具都补充同一份模型</h3>
<p>Nmap、Nuclei、浏览器、Kali 工具集、导入的取证材料和外部系统都向同一模型写入可追溯的观察结果，而不是各自留下孤立报告。</p>
</section>

<section class="card">
<span class="card-label">实时工作台</span>
<h3>耗时任务不阻塞操作</h3>
<p>左侧执行命令，右侧实时更新当前工作视图中的对象、证据、发现项、攻击路径或时间线。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>从初始扫描到安全对象模型（Security Object Model）</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 数据流">
<pre><code>内置扫描器
      ↓
   安全对象
      ↑
工具 / 数据源
      ↓
观察结果 + 证据
      ↓
发现项 + 关联关系
      ↓
可达性 / 攻击路径</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>内置扫描器建立初始模型，现有工具继续补充和验证</strong></p>
<p>工具直接融入工作台：内置检查、常用命令行工具、浏览器、负载生成器、外部扫描器和集成都把结果汇入同一工作空间，而不是形成多套彼此割裂的数据。</p>
<p class="workbench-note">1337 核心可在本地运行，默认不要求部署端点代理。大型扫描器、Kali 工具集、浏览器运行时、搜索索引和厂商连接器均按需启用。</p>
</div>
</div>
</section>

<section class="content-section">
<h2>同一模型，四种专业工作视图（lenses）</h2>
<div class="grid">
<section class="card">
<span class="card-label">Pentest</span>
<h3>攻击面与攻击路径</h3>
<p>聚焦侦察、发现项、凭据、横向移动、网络可达性、攻击路径和受控验证，同时保留对常用工具的直接访问。</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>证据与攻击过程重建</h3>
<p>聚焦证据来源、取证材料、IOC、时间线、实体关联、置信度和基于证据的事件重建；每个关键结论都能回溯到原始证据。</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>从源代码到运行环境</h3>
<p>将源代码、依赖、SBOM、镜像、部署、API、运行时关联和安全发现统一到同一模型，并支持可复现的安全门禁。</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>攻击、检测、防护、复测</h3>
<p>把授权的攻击动作与遥测数据、检测告警、防护控制和复测结果关联在同一模型中。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>核心架构</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>安全对象模型（Security Object Model）</h3><p>统一描述目标、资产、服务、端点、身份、证据、发现项、关联关系、网络可达性和攻击路径。</p></section>
<section class="architecture-card"><h3>内置发现（Native Discovery）</h3><p>无需强制安装外部扫描器或集成，即可先建立目标系统的初始黑盒模型。</p></section>
<section class="architecture-card"><h3>模块化工具（Modular Tooling）</h3><p>内置引擎与可替换的外部工具通过统一能力接口接入，不把工作台绑定到某个扫描器或发行版。</p></section>
<section class="architecture-card"><h3>证据与来源追踪（Evidence &amp; Provenance）</h3><p>观察结果与结论始终保留来源、授权范围、时间、工具、执行器和相关支撑材料。</p></section>
<section class="architecture-card"><h3>授权范围与执行策略（Scope &amp; Policy）</h3><p>明确约束授权范围和影响级别，负责限制执行边界，但不取代工作台本身。</p></section>
<section class="architecture-card"><h3>工作视图与接口（Lenses &amp; Interfaces）</h3><p>TUI、Web、API、SDK、MCP、CI 和 AI 都基于同一底层状态，通过不同工作视图访问。</p></section>
</div>
<p class="invariant"><strong>一个安全对象模型 · 多种工作视图 · 任意合适的工具</strong></p>
</section>

<section class="content-section">
<h2>M4 展示：可复现的攻击路径</h2>
<div class="roadmap-panel">
<div class="roadmap-heading">
<span class="status roadmap-status">M4 路线图 · 可复现实验环境</span>
<a href="https://github.com/Fuzzy-Technologies/1337/issues/115">展示规范 #115 →</a>
</div>

<p>M4 计划提供一个由项目仓库维护的 Docker Compose 实验环境，在同一份 1337 模型上复现三类攻击路径。用户可以在本地启动实验环境，使用已授权工具进行评估，查看证据，验证攻击路径，应用防护控制，并重新计算攻击图。</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">业务关键路径</span>
<p><strong>Internet → 客户门户 → 用户身份 → Billing API → 关键业务操作</strong></p>
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

<blockquote><strong>哪些通往关键资产的攻击路径确实可达？哪些证据能够证明？哪项安全控制能够切断这条链路？</strong></blockquote>
<p class="quiet">M4 仍属于路线图内容，并不包含在 v0.1.8 中。目标是可复现的 Docker Compose 实验环境，而不是预先录制的演示。</p>
<p class="showcase-hook"><strong>启动实验环境 · 复现问题 · 验证攻击路径 · 确认修复效果</strong></p>
</div>
</section>

<section class="content-section">
<h2>当前已经可用的内容</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">v0.1.8 已提供</span>
<h3>可运行的 pre-alpha 工程基础</h3>
<ul>
<li>Apache-2.0 开源核心</li>
<li>可安装的 1337 与 1337-dev 命令</li>
<li>命令注册机制（Command Registry）基础</li>
<li>项目仓库自带的隔离测试环境</li>
<li>基于 pytest 的功能测试基础</li>
<li>公开、版本化的接口契约和架构文档</li>
<li>跨平台的确定性质量检查</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">后续里程碑</span>
<h3>正在开发</h3>
<ul>
<li>实时双栏终端工作台</li>
<li>内置发现能力与最小安全对象模型</li>
<li>可插拔扫描器和工具，以及 Quick Scan</li>
<li>Pentest、DFIR、DevSecOps 与 Purple Team 工作视图</li>
<li>证据、可达性分析与攻击路径</li>
<li>API/SDK/MCP 与厂商系统集成</li>
</ul>
</section>
</div>
<p class="section-hook">只有经过代码、测试和公开接口契约验证的能力才视为已实现；其余内容均明确标注为路线图</p>
</section>

<section class="content-section">
<h2>项目资源</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">架构愿景</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">AI 智能体集成</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">ADR 0010：工作台架构</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">安全策略</a>
</div>
</section>

<section class="content-section">
<h2>负责任地使用</h2>
<p>1337 用于防御性安全工程、经授权的渗透测试与调查、培训、研究、CTF / 实验环境，以及你拥有或已获得明确授权进行测试的系统。</p>
<p>未经授权，不得使用本项目扫描、探测、利用或干扰第三方系统。</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">技术 · 知识 · 科学</span>
</footer>
