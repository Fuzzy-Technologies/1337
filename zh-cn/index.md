---
layout: default
lang: zh-CN
title: 1337 Security Workbench
description: Fuzzy Technologies 的 1337 Security Workbench —— 面向安全从业者的开放式网络安全工作台，以及面向网络安全 AI 智能体、与具体模型和提供商解耦的运行时。
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
<p class="eyebrow">开放式网络安全工作台 · 面向网络安全 AI 智能体 (AI security agents) 的模型无关运行时 (model-agnostic runtime)</p>
<p class="hero-hook">工具负责发现问题。<br><strong>1337 负责保存安全状态</strong></p>
<span class="status">早期 pre-alpha · Apache-2.0 Community core · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>面向渗透测试人员、安全工程师、研究人员和安全团队的开放式安全工作台。1337 将专业工具的输出转化为来源可追溯的证据 (attributable evidence) 和可持久保存的安全状态，用于可达性分析 (reachability analysis) 与攻击路径分析 (attack-path analysis)。</p>
<blockquote class="hero-quote"><strong>模型负责推理。1337 保存状态、管控执行并保存证据</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Pre-release v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">路线图</a>
</div>
</div>
</section>

<section class="content-section">
<h2>扫描只是开始</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">工具孤岛</span>
<h3>扫描器输出不等于安全状态</h3>
<p>Nmap 知道开放端口，Nuclei 知道模板命中结果，浏览器知道当前会话，报告只是某一时刻的快照。最终仍需要操作人员把这些碎片关联起来。</p>
</section>

<section class="card">
<span class="card-label">AI 需要持久上下文</span>
<h3>推理不是持久化记忆</h3>
<p>AI 模型可以分析一次安全评估，但聊天会话并不是资产模型、授权边界、证据存储，也不是攻击图。</p>
</section>

<section class="card">
<span class="card-label">风险优先级</span>
<h3>严重性等级并不能告诉你攻击路径</h3>
<p>一个高严重性发现项并不能说明攻击者是否能够到达关键资产、多个暴露面如何串成链路，也不能说明哪项安全控制措施能够切断这条链。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>从工具输出到安全状态</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="1337 证据流">
<pre><code>工具 / 扫描器
      ↓
     证据
      ↓
安全对象 (Security Objects)
      ↓
发现项 (Findings)
      ↓
    可达性
      ↓
   攻击路径
      ↓
  下一步决策</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>1337 不替代你的工具箱，而是在其周围提供统一的状态与证据层</strong></p>
<p>专业工具继续做它们最擅长的事情。1337 的目标是把这些结果保存为来源可追溯的证据，与持久化的安全对象关联起来，并让同一份安全状态能够被人员、自动化流程和未来的 AI 智能体重复使用。</p>
<p class="workbench-note">1337 的价值从传统工具通常停止的地方开始：工具已经产生输出，但证据、可达性、安全上下文和下一步决策还没有被连接起来。</p>
</div>
</div>
</section>

<section class="content-section">
<h2>一个核心，多种工作流</h2>
<div class="grid">
<section class="card">
<span class="card-label">安全从业者</span>
<h3>渗透测试人员与安全工程师</h3>
<p>把工具输出、证据、授权测试范围 (scope) 和调查上下文保存在同一个工作空间中，不必再从终端历史和零散笔记里重新拼出关键攻击路径。</p>
</section>

<section class="card">
<span class="card-label">AI 与自动化</span>
<h3>AI 智能体开发者</h3>
<p>把组织信任的 AI 模型连接到同一套结构化安全状态和类型化能力。授权范围、执行策略和证据由 1337 管控，不交由模型自行决定，因此更换模型时无需重新设计整个工作流。</p>
<p class="card-hook">使用你信任的模型。1337 提供安全工作台</p>
</section>

<section class="card">
<span class="card-label">安全运营</span>
<h3>安全团队</h3>
<p>持续关联发现项、身份、安全控制措施和资产，让团队把注意力放在真正可达的风险、攻击路径，以及最能降低暴露面的修复措施上。</p>
</section>
</div>
</section>

<section class="content-section">
<h2>核心架构</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>安全对象模型 (Security Object Model)</h3><p>面向资产、服务、端点、身份、安全控制措施、证据、发现项、可达性和攻击路径的共享模型。</p></section>
<section class="architecture-card"><h3>能力层 (Capability Fabric)</h3><p>以类型化方式调用安全能力，使工作流不必绑定到某一个扫描器、工具或 AI 提供商。</p></section>
<section class="architecture-card"><h3>授权范围与策略 (Scope &amp; Policy)</h3><p>显式定义授权范围、目标、影响级别和执行约束，这些边界独立于模型自身的判断。</p></section>
<section class="architecture-card"><h3>受控执行运行时 (Executor Runtime)</h3><p>在受控环境中运行工具和原生能力，而不是默认向智能体提供不受限制的 shell 访问。</p></section>
<section class="architecture-card"><h3>证据与来源可追溯性 (Evidence &amp; Provenance)</h3><p>重要结论始终可以追溯到来源、授权范围、时间、工具、执行器以及相关支撑材料。</p></section>
<section class="architecture-card"><h3>可达性与攻击图 (Reachability &amp; Attack Graph)</h3><p>把暴露面、身份关系和安全控制措施关联为通往关键资产与关键结果的攻击路径。</p></section>
</div>
<p class="invariant"><strong>模型可以替换，安全状态必须持续保留</strong></p>
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
<li>交互式 shell 与 workspace UX</li>
<li>生产级扫描器适配器</li>
<li>发现项与可达性工作流</li>
<li>攻击图 UX</li>
<li>AI 智能体接口</li>
<li>企业级能力</li>
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
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0008-ai-native-cyber-execution-platform.md">AI-native platform</a>
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
