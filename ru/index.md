---
layout: default
lang: ru
title: 1337 Security Workbench
description: 1337 Security Workbench от Fuzzy Technologies — открытая локальная рабочая среда для пентеста, расследований и инженерного анализа безопасности с живой моделью объектов ИБ и подключаемыми инструментами.
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
<p class="eyebrow">Открытая рабочая среда ИБ · Живая модель объектов · Подключаемые инструменты</p>
<p class="hero-hook">Исследуйте систему.<br><strong>Стройте её модель по мере работы</strong></p>
<span class="status">Pre-alpha · Apache-2.0 · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>Быстрая локальная среда для пентеста, расследований и инженерного анализа безопасности. Встроенный сканер строит первичную модель системы, а подключаемые инструменты дополняют её наблюдениями, доказательствами, выявленными проблемами, связями, данными о достижимости и путях атаки.</p>
<blockquote class="hero-quote"><strong>ИИ-модели рассуждают. 1337 хранит состояние, контролирует выполнение и сохраняет доказательства</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Предварительный релиз v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">План разработки</a>
</div>
</div>
</section>

<section class="content-section">
<h2>Одна живая модель вместо разрозненных результатов</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Встроенный сканер</span>
<h3>Первичная модель — без обязательных внешних инструментов</h3>
<p>1337 сам обнаруживает цели, хосты, сервисы, конечные точки, технологии и связи. По мере подключения дополнительных инструментов и источников данных модель уточняется и расширяется.</p>
</section>

<section class="card">
<span class="card-label">Единая модель</span>
<h3>Все инструменты дополняют одно состояние</h3>
<p>Nmap, Nuclei, браузеры, инструменты Kali, импортированные артефакты и внешние системы добавляют проверяемые наблюдения в одну модель, а не создают набор несвязанных отчётов.</p>
</section>

<section class="card">
<span class="card-label">Живой интерфейс</span>
<h3>Долгие задачи не останавливают работу</h3>
<p>Слева запускаются команды, а справа в реальном времени обновляется выбранный срез модели: объекты, доказательства, выявленные проблемы, пути атаки или хронология.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>От первичного сканирования — к модели объектов ИБ (Security Object Model)</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="Поток данных 1337">
<pre><code>Встроенный сканер
        ↓
    Объекты ИБ
        ↑
Инструменты / источники
        ↓
Наблюдения + доказательства
        ↓
Проблемы + связи
        ↓
Достижимость / пути атаки</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>Встроенный сканер строит первичную модель. Ваши инструменты обогащают её</strong></p>
<p>Инструменты — полноценная часть 1337: встроенные проверки, привычные консольные утилиты, браузеры, генераторы нагрузки, внешние сканеры и интеграции передают результаты в единое рабочее пространство вместо набора разрозненных хранилищ.</p>
<p class="workbench-note">Базовый 1337 работает локально и не требует установки агентов. Тяжёлые сканеры, наборы инструментов Kali, браузерные движки, поисковые индексы и интеграции подключаются только при необходимости.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>Одна модель — четыре рабочих представления (lenses)</h2>
<div class="grid">
<section class="card">
<span class="card-label">Пентест</span>
<h3>Поверхность атаки и пути проникновения</h3>
<p>Разведка, выявленные проблемы, учётные данные, точки опоры, достижимость, пути атаки и контролируемая проверка эксплуатации — с прямым доступом к привычным инструментам.</p>
</section>

<section class="card">
<span class="card-label">DFIR</span>
<h3>Доказательства и реконструкция атаки</h3>
<p>Происхождение данных, артефакты, индикаторы компрометации (IOC), хронология, связи и подтверждённый данными маршрут злоумышленника. Каждый существенный вывод остаётся привязан к исходным доказательствам.</p>
</section>

<section class="card">
<span class="card-label">DevSecOps</span>
<h3>От исходного кода до среды выполнения</h3>
<p>Репозиторий, зависимости, SBOM, образы, развёртывания, API, связи с рабочей средой и результаты проверок — в одной модели с воспроизводимыми проверками безопасности.</p>
</section>

<section class="card">
<span class="card-label">Purple Team</span>
<h3>Атака, детектирование, защита, повторная проверка</h3>
<p>Одна модель связывает разрешённые действия атакующей стороны с телеметрией, срабатываниями средств защиты, защитными мерами и результатами повторной проверки.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Архитектурное ядро</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Модель объектов ИБ (Security Object Model)</h3><p>Единая модель целей, активов, сервисов, конечных точек, учётных записей, доказательств, выявленных проблем, связей, достижимости и путей атаки.</p></section>
<section class="architecture-card"><h3>Встроенное обнаружение (Native Discovery)</h3><p>Строит исходную модель исследуемой системы без обязательной установки внешних сканеров и интеграций.</p></section>
<section class="architecture-card"><h3>Модульные инструменты (Modular Tooling)</h3><p>Встроенные механизмы и заменяемые внешние инструменты предоставляют нужные возможности без привязки к одному сканеру или дистрибутиву.</p></section>
<section class="architecture-card"><h3>Доказательства и происхождение данных (Evidence &amp; Provenance)</h3><p>Наблюдения и выводы остаются привязаны к источнику, границам проверки, времени, инструменту, среде выполнения и подтверждающим материалам.</p></section>
<section class="architecture-card"><h3>Границы проверки и правила выполнения (Scope &amp; Policy)</h3><p>Явно задают разрешённую область проверки и допустимое воздействие, ограничивая выполнение операций, но не подменяя собой рабочую среду.</p></section>
<section class="architecture-card"><h3>Рабочие представления и интерфейсы (Lenses &amp; Interfaces)</h3><p>Терминальный и веб-интерфейсы, API, SDK, MCP, CI и ИИ используют одно состояние через разные рабочие представления.</p></section>
</div>
<p class="invariant"><strong>Одна модель объектов ИБ · Несколько рабочих представлений · Любой подходящий инструмент</strong></p>
</section>

<section class="content-section">
<h2>Демо M4: воспроизводимые пути атаки</h2>
<div class="roadmap-panel">
<div class="roadmap-heading">
<span class="status roadmap-status">M4 · план разработки · воспроизводимый стенд</span>
<a href="https://github.com/Fuzzy-Technologies/1337/issues/115">Спецификация #115 →</a>
</div>

<p>В M4 появится воспроизводимый стенд на Docker Compose с тремя сценариями атаки, работающими поверх одной модели 1337. Пользователь сможет локально поднять стенд, исследовать его разрешёнными инструментами, изучить доказательства, подтвердить путь атаки, применить меру защиты и пересчитать граф.</p>

<div class="case-grid">
<section class="case-card">
<span class="card-label">Критичный бизнес-сценарий</span>
<p><strong>Интернет → Портал клиента → Учётная запись → Billing API → Критичная бизнес-операция</strong></p>
</section>

<section class="case-card">
<span class="card-label">Привилегии и доступ</span>
<p><strong>Интернет → Портал поддержки → Учётная запись → SSO/IAM → Консоль администратора</strong></p>
</section>

<section class="case-card">
<span class="card-label">Цепочка поставки ПО</span>
<p><strong>Репозиторий → CI Job → Runner → Artifact Registry → Deployment → Production</strong></p>
</section>
</div>

<blockquote><strong>Какие пути к критичным активам действительно достижимы, какими доказательствами это подтверждается и какая мера защиты разрывает цепочку?</strong></blockquote>
<p class="quiet">M4 пока входит только в план разработки и не является частью v0.1.8. Цель — воспроизводимый стенд на Docker Compose, а не заранее записанная демонстрация.</p>
<p class="showcase-hook"><strong>Поднять стенд · воспроизвести проблему · подтвердить путь атаки · проверить исправление</strong></p>
</div>
</section>

<section class="content-section">
<h2>Что уже работает</h2>
<div class="proof-grid">
<section class="proof-card proof-now">
<span class="card-label">В v0.1.8</span>
<h3>Рабочая инженерная база pre-alpha-версии</h3>
<ul>
<li>открытое ядро под лицензией Apache-2.0</li>
<li>устанавливаемые команды 1337 и 1337-dev</li>
<li>базовый реестр команд (Command Registry)</li>
<li>изолированный тестовый стенд из репозитория</li>
<li>базовый функциональный тестовый контур на pytest</li>
<li>публичные версионируемые контракты и архитектурная документация</li>
<li>детерминированные проверки качества на нескольких платформах</li>
</ul>
</section>

<section class="proof-card">
<span class="card-label">Следующие этапы</span>
<h3>В разработке</h3>
<ul>
<li>живой двухпанельный терминальный интерфейс</li>
<li>встроенное обнаружение и минимальная модель объектов ИБ (Security Object Model)</li>
<li>подключаемые сканеры и инструменты, Quick Scan</li>
<li>рабочие представления для Pentest, DFIR, DevSecOps и Purple Team</li>
<li>доказательства, анализ достижимости и пути атаки</li>
<li>API/SDK/MCP и интеграции с внешними продуктами</li>
</ul>
</section>
</div>
<p class="section-hook">Реализованными считаем только возможности, подтверждённые кодом, тестами и публичными контрактами. Остальное явно помечается как планы</p>
</section>

<section class="content-section">
<h2>Документация и материалы</h2>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Архитектурное видение</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">ИИ и интеграция агентов</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0010-live-security-object-model-modular-tooling-and-lenses.md">ADR 0010: архитектура рабочего места</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">Политика безопасности</a>
</div>
</section>

<section class="content-section">
<h2>Ответственное использование</h2>
<p>1337 предназначен для защитной инженерии ИБ, разрешённых пентестов, расследований, обучения, исследований, CTF и лабораторных сред, а также для систем, которыми вы владеете или на проверку которых у вас есть явное разрешение.</p>
<p>Не используйте проект для сканирования, эксплуатации уязвимостей или нарушения работы чужих систем без разрешения.</p>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
<span class="footer-motto">Технологии · Знания · Наука</span>
</footer>
