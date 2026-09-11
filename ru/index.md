---
layout: default
lang: ru
title: 1337 Security Workbench
description: 1337 Security Workbench от Fuzzy Technologies — локальная рабочая среда ИБ с живой моделью объектов и модульным набором security-инструментов.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Навигация по сайту">
<div class="language-switch" aria-label="Язык">
<a class="lang-button" href="{{ '/' | relative_url }}">EN</a>
<a class="lang-button active" href="{{ '/ru/' | relative_url }}" aria-current="page">RU</a>
<a class="lang-button" href="{{ '/zh-cn/' | relative_url }}">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.github.io/ru/" aria-label="Fuzzy Technologies">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid">
<div class="hero-primary">
<p class="eyebrow">Открытая рабочая среда ИБ · Живая модель объектов · Модульный security tooling</p>
<p class="hero-hook">Исследуй систему.<br><strong>Строй её модель прямо во время работы</strong></p>
<span class="status">Pre-alpha · Community core (Apache-2.0) · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>Быстрая local-first рабочая среда для практической ИБ. Встроенное обнаружение строит исходную модель, а подключаемые инструменты обогащают её доказательствами, находками, связями, достижимостью и путями атаки.</p>
<blockquote class="hero-quote"><strong>ИИ-модели рассуждают. 1337 хранит состояние, управляет выполнением и сохраняет доказательства</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Пре-релиз v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">Роадмап</a>
</div>
</div>
</section>

<section class="content-section">
<h2>Одна живая модель вместо россыпи отчётов</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Встроенное обнаружение</span>
<h3>Полезная модель ещё до установки внешних тулов</h3>
<p>1337 должен сам находить базовые цели, хосты, сервисы, endpoints, технологии и связи, а затем расширять эту картину по мере подключения новых сенсоров.</p>
</section>

<section class="card">
<span class="card-label">Общее состояние</span>
<h3>Все сенсоры обогащают одну модель</h3>
<p>Nmap, Nuclei, браузеры, Kali tool packs, импортированные артефакты и интеграции добавляют атрибутированные наблюдения, а не создают независимые острова результатов.</p>
</section>

<section class="card">
<span class="card-label">Живой Workbench</span>
<h3>Долгие задачи не блокируют оператора</h3>
<p>Слева выполняются команды, справа постепенно обновляется нужный срез модели: объекты, доказательства, findings, пути или timeline текущей линзы.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>От обнаружения — к устойчивой Security Object Model</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="Поток данных 1337">
<pre><code>Встроенное обнаружение
        ↓
   Объекты ИБ
        ↑
 Инструменты / сенсоры
        ↓
Наблюдения + доказательства
        ↓
Находки + связи
        ↓
Достижимость / пути</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>Встроенное обнаружение начинает модель. Ваши инструменты делают её богаче</strong></p>
<p>Tooling — часть рабочего места: встроенные capability, привычные CLI, браузеры, workload engines, vendor scanners и будущие интеграции работают с одним workspace вместо набора разрозненных баз.</p>
<p class="workbench-note">Core остаётся local-first и agentless-first. Тяжёлые сканеры, Kali packs, браузеры, поисковые индексы и vendor-коннекторы подключаются только когда нужны.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>Одна модель — четыре начальные линзы</h2>
<div class="grid">
<section class="card">
<span class="card-label">Pentest</span>
<h3>Поверхность атаки и следующий доступный шаг</h3>
<p>Recon, findings, credentials, pivots, достижимость, пути атаки и ограниченная validation с прямым доступом к привычным инструментам.</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>Доказательства и наблюдавшийся путь злоумышленника</h3>
<p>Provenance, entities, IOC, timeline, confidence и реконструкция инцидента по тем же объектам и доказательствам.</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>От кода до артефакта и runtime</h3>
<p>Source, dependencies, SBOM, images, deployments, API, runtime relations, findings и детерминированные security gates.</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>Действие, детект, мера защиты, retest</h3>
<p>Одна модель связывает разрешённые offensive-действия с telemetry, detections, controls и состоянием до/после проверки.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Архитектурное ядро</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Security Object Model</h3><p>Устойчивое ядро для целей, активов, сервисов, endpoints, identities, evidence, findings, связей, достижимости и путей.</p></section>
<section class="architecture-card"><h3>Native Discovery</h3><p>Исходная black-box модель строится без обязательной установки внешних сканеров и интеграций.</p></section>
<section class="architecture-card"><h3>Модульный tooling</h3><p>Встроенные engines и заменяемые внешние providers дают capability без обязательной привязки к одному сканеру или дистрибутиву.</p></section>
<section class="architecture-card"><h3>Evidence &amp; Provenance</h3><p>Наблюдения и выводы остаются привязаны к источнику, scope, времени, tool, executor и supporting artifacts.</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Границы разрешённой работы и impact управляют действиями, но не являются самим продуктом.</p></section>
<section class="architecture-card"><h3>Lenses &amp; Interfaces</h3><p>TUI, Web, API, SDK, MCP, CI и AI используют одно состояние через разные рабочие срезы.</p></section>
</div>
<p class="invariant"><strong>Одна Security Object Model · Несколько линз · Любой подходящий инструмент</strong></p>
</section>

<section class="content-section">
<h2>Демо M4: три воспроизводимых сценария</h2>
<div class="roadmap-panel">
<div class="roadmap-heading">
<span class="status roadmap-status">M4 · роадмап · воспроизводимый стенд</span>
<a href="https://github.com/Fuzzy-Technologies/1337/issues/115">Спецификация #115 →</a>
</div>

<p>В M4 планируем стенд на Docker Compose: одна инфраструктура, три сценария пути атаки, единое состояние 1337. Пользователь сможет поднять стенд локально, просканировать его разрешёнными инструментами, проверить доказательства, подтвердить путь и увидеть, как защитная мера меняет граф.</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">Бизнес-критичный сценарий</span>
<p><strong>Интернет → Портал клиента → Учётная запись → Billing API → Критичная бизнес-операция</strong></p>
</section>

<section class="case-card">
<span class="card-label">Привилегии и доступ</span>
<p><strong>Интернет → Support Portal → Учётная запись → SSO/IAM → Admin Console</strong></p>
</section>

<section class="case-card">
<span class="card-label">Цепочка поставки ПО / CI/CD</span>
<p><strong>Репозиторий → CI job → Runner → Artifact Registry → Deployment → Production</strong></p>
</section>
</div>

<blockquote><strong>Какие пути к критичным активам реально доступны злоумышленнику, чем это подтверждено и какая мера защиты разрывает цепочку?</strong></blockquote>
<p class="quiet">M4 пока в роадмапе и не входит в v0.1.8. Цель — воспроизводимый Compose-стенд, а не заранее записанная демонстрация.</p>
<p class="showcase-hook"><strong>Поднять стенд · воспроизвести результаты · проверить путь атаки · подтвердить эффект исправления</strong></p>
</div>
</section>

<section class="content-section">
<h2>Что уже работает</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">В v0.1.8</span>
<h3>Воспроизводимая основа pre-alpha-версии</h3>
<ul>
<li>Community core под Apache-2.0</li>
<li>CLI-команды 1337 / 1337-dev</li>
<li>базовый Command Registry</li>
<li>изолированный синтетический стенд из репозитория</li>
<li>функциональные тесты на pytest</li>
<li>публичные версионируемые контракты и архитектурная документация</li>
<li>детерминированные проверки качества на нескольких платформах</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">Дальше по роадмапу</span>
<h3>Продуктовые возможности в разработке</h3>
<ul>
<li>живой split-pane terminal workbench</li>
<li>native discovery и минимальная Security Object Model</li>
<li>модульные scanner/tool providers и Quick Scan</li>
<li>Pentest / DFIR / DevSecOps / Purple lenses</li>
<li>evidence, reachability и attack-path workflows</li>
<li>API/SDK/MCP и vendor integrations</li>
</ul>
</section>
</div>
<p class="section-hook">Текущие возможности подтверждаются кодом, тестами и публичными контрактами; всё остальное остаётся в роадмапе</p>
</section>

<section class="content-section">
<h2>Документация и материалы</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Архитектурное видение</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">Архитектура ИИ-агентов</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">Архитектура Live Workbench</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">Политика безопасности</a>
</div>
</section>

<section class="content-section">
<h2>Ответственное использование</h2>
<p>1337 предназначен для защитной инженерии ИБ, разрешённых пентестов, обучения, исследований, CTF и лабораторных сред, а также систем, которыми вы владеете или на проверку которых у вас есть явное разрешение.</p>
<p>Не используйте проект для сканирования, эксплуатации уязвимостей или нарушения работы чужих систем без разрешения.</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">Технологии · Знания · Наука</span>
</footer>
