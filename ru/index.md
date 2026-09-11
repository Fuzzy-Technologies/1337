---
layout: default
lang: ru
title: 1337 Security Workbench
description: 1337 Security Workbench от Fuzzy Technologies — открытая рабочая среда ИБ и рантайм для ИИ-агентов без привязки к конкретной модели.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Навигация по сайту">
<div class="language-switch" aria-label="Язык">
<a class="lang-button" href="{{ '/' | relative_url }}">EN</a>
<a class="lang-button active" href="{{ '/ru/' | relative_url }}" aria-current="page">RU</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.github.io/ru/" aria-label="Fuzzy Technologies">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid">
<div class="hero-primary">
<p class="eyebrow">Открытая рабочая среда ИБ · Рантайм для ИИ-агентов в ИБ без привязки к конкретной модели</p>
<p class="hero-hook">Инструменты находят факты.<br><strong>1337 сохраняет состояние защищённости</strong></p>
<span class="status">Pre-alpha · Community core (Apache-2.0) · v0.1.8</span>
</div>

<div class="hero-secondary">
<p>Открытая рабочая среда для пентестеров, инженеров ИБ, исследователей и команд безопасности. 1337 связывает результаты специализированных инструментов с доказательствами и контекстом, формируя устойчивое состояние защищённости для анализа достижимости и путей атаки.</p>
<blockquote class="hero-quote"><strong>ИИ-модели рассуждают. 1337 хранит состояние, управляет выполнением и сохраняет доказательства</strong></blockquote>
<div class="links hero-actions">
<a href="https://github.com/Fuzzy-Technologies/1337">GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Пре-релиз v0.1.8</a>
<a href="https://github.com/Fuzzy-Technologies/1337/milestones">Роадмап</a>
</div>
</div>
</section>

<section class="content-section">
<h2>Сканирование — только начало</h2>
<div class="grid problem-grid">
<section class="card">
<span class="card-label">Разрозненные инструменты</span>
<h3>Результаты сканеров — ещё не картина защищённости</h3>
<p>Nmap видит порты, Nuclei — срабатывания шаблонов, браузер — текущую сессию, отчёт — снимок на момент времени. Связать всё это в одну картину обычно приходится вручную.</p>
</section>

<section class="card">
<span class="card-label">ИИ нужен устойчивый контекст</span>
<h3>Анализ модели — не долговременная память</h3>
<p>ИИ может разобрать результаты проверки, но чат не заменяет реестр активов, границы разрешённой проверки, историю доказательств и граф атак.</p>
</section>

<section class="card">
<span class="card-label">Приоритизация</span>
<h3>Критичность не показывает реальный путь атаки</h3>
<p>Даже проблема критического уровня сама по себе не отвечает на три вопроса: достижима ли важная цель, как уязвимости и права складываются в цепочку и какая мера защиты эту цепочку разорвёт.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>От результатов инструментов — к состоянию защищённости</h2>
<div class="workbench-grid">
<div class="flow-panel" aria-label="Поток данных 1337">
<pre><code>Инструмент / сканер
        ↓
   Доказательства
        ↓
     Объекты ИБ
        ↓
Результаты проверки
        ↓
   Достижимость
        ↓
    Пути атаки
        ↓
      Решение</code></pre>
</div>

<div class="workbench-copy">
<p class="section-hook"><strong>1337 не заменяет ваш набор инструментов. Он добавляет единый слой состояния и доказательств</strong></p>
<p>Сканеры, прокси, браузеры и другие специализированные инструменты остаются на своих местах. 1337 сохраняет результаты как проверяемые доказательства, связывает их с объектами ИБ и делает полученное состояние пригодным для повторного анализа людьми, автоматизацией и будущими ИИ-агентами.</p>
<p class="workbench-note">То, что обычно теряется между терминалом, заметками и отчётом, становится общей моделью: с источником данных, контекстом, достижимостью и связью с последующими решениями.</p>
</div>
</div>
</section>

<section class="content-section">
<h2>Одно ядро — разные сценарии работы</h2>
<div class="grid">
<section class="card">
<span class="card-label">Практическая ИБ</span>
<h3>Пентестеры и инженеры ИБ</h3>
<p>1337 рассчитан на работу с привычными ИБ-инструментами так, чтобы результаты, доказательства, границы проверки и контекст исследования не приходилось заново собирать по истории терминала и заметкам.</p>
</section>

<section class="card">
<span class="card-label">ИИ и автоматизация</span>
<h3>ИИ-агенты для ИБ</h3>
<p>ИИ-модель можно менять независимо от рабочего контура: 1337 хранит границы проверки, состояние, правила выполнения и доказательства вне модели. Агент получает формализованные операции и актуальный контекст вместо неограниченного доступа к shell.</p>
<p class="card-hook">Своя ИИ-модель. Единый рабочий контур 1337</p>
</section>

<section class="card">
<span class="card-label">Операционная ИБ</span>
<h3>Команды безопасности</h3>
<p>Единый контекст по активам, результатам проверок, идентичностям и защитным мерам помогает фокусироваться на реально достижимых рисках, путях атаки и исправлениях с наибольшим эффектом.</p>
</section>
</div>
</section>

<section class="content-section">
<h2>Архитектурное ядро</h2>
<div class="architecture-grid">
<section class="architecture-card"><h3>Модель объектов ИБ</h3><p>Единая модель для активов, сервисов, конечных точек, идентичностей, защитных мер, доказательств, результатов проверок, достижимости и путей атаки.</p></section>
<section class="architecture-card"><h3>Capability Fabric</h3><p>Типизированный слой операций ИБ без жёсткой привязки сценария работы к конкретному сканеру, инструменту или поставщику ИИ-модели.</p></section>
<section class="architecture-card"><h3>Scope &amp; Policy</h3><p>Явные границы разрешённой проверки, воздействия и выполнения, которые не зависят от решения ИИ-модели.</p></section>
<section class="architecture-card"><h3>Контролируемый рантайм</h3><p>Запуск инструментов и встроенных операций через управляемый контур вместо неограниченного shell-доступа.</p></section>
<section class="architecture-card"><h3>Доказательства и происхождение данных</h3><p>Существенные выводы остаются привязаны к источнику, границам проверки, времени, инструменту, исполнителю и подтверждающим артефактам.</p></section>
<section class="architecture-card"><h3>Достижимость и граф атак</h3><p>Уязвимости, права, идентичности и защитные меры связываются в пути к критичным активам и последствиям.</p></section>
</div>
<p class="invariant"><strong>ИИ-модель можно заменить. Состояние защищённости — нет</strong></p>
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
<li>интерактивная консоль и рабочее пространство</li>
<li>адаптеры реальных сканеров</li>
<li>анализ результатов и достижимости</li>
<li>интерфейс графа атак</li>
<li>интерфейсы для ИИ-агентов</li>
<li>корпоративные возможности</li>
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
<a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0008-ai-native-cyber-execution-platform.md">AI-native platform</a>
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
