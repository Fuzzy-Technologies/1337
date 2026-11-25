---
layout: default
lang: ru
title: 1337 Security Workbench
description: Открытая рабочая среда для задач информационной безопасности от Fuzzy Technologies. Запускайте согласованные проверки, сохраняйте доказательства и разбирайте результаты офлайн.
---

<header class="site-header">
<h1 class="site-title">1337 Security Workbench</h1>
<nav class="top-actions" aria-label="Навигация по сайту">
<div class="language-switch" aria-label="Язык">
<a class="lang-button" href="{{ '/' | relative_url }}">EN</a>
<a class="lang-button active" href="{{ '/ru/' | relative_url }}" aria-current="page">RU</a>
<a class="lang-button" href="{{ '/zh-cn/' | relative_url }}">简中</a>
</div>
<a class="brand-button" href="https://fuzzy-technologies.com/ru/">Fuzzy Technologies ↗</a>
</nav>
</header>

<section class="hero hero-grid" aria-labelledby="intro">
<div class="hero-secondary">
<p class="eyebrow">Открытая рабочая среда для ИБ</p>
<h2 class="hero-hook" id="intro">Проверяйте системы.<br><strong>Сохраняйте доказательства.</strong></h2>
<p>1337 собирает согласованные проверки, их результаты и исходные доказательства в одном локальном рабочем пространстве. К результатам можно вернуться, проверить, на чём основан каждый вывод, и передать отчёт коллегам, даже если проверенная система уже недоступна.</p>
<div class="links hero-actions">
<a class="primary-action" href="#get-started">Попробовать демо</a>
<a href="#roadmap">Планы развития</a>
</div>
</div>
<figure class="hero-primary">
<img class="hero-image" src="{{ '/static/images/1337-logo.png' | relative_url }}" alt="Мария за рабочим столом 1337, иллюстрация проекта" width="1774" height="887" decoding="async" fetchpriority="high" />
</figure>
</section>

<section class="content-section">
<h2 id="workflow">От проверки к отчёту</h2>
<div class="grid">
<article class="card">
<h3>Задайте область проверки</h3>
<p>Выберите системы и проверки, на которые у вас есть разрешение. Политика определяет допустимые действия и где нужно подтверждение.</p>
</article>
<article class="card">
<h3>Соберите картину системы</h3>
<p>Модель объектов ИБ связывает активы, сервисы, конечные точки и обнаруженные проблемы с исходными наблюдениями и доказательствами.</p>
</article>
<article class="card">
<h3>Разберите результаты офлайн</h3>
<p>Откройте сохранённое рабочее пространство, проследите вывод до первоисточника и выгрузите отчёт без повторного обращения к системе.</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="community">Доступно в Community v0.3.0</h2>
<p>Начать можно с демо, которое целиком работает на вашем компьютере. В релизе есть интерактивная консоль, базовые HTTP-проверки и собственные веб-проверки, а также сценарии с Nmap, Nuclei и Trivy. Рабочее пространство можно сохранить, а отчёты выгрузить в HTML, JSON, SARIF или JUnit. В CI можно запускать согласованные проверки и принимать решение по заданным критериям.</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0">Что вошло в релиз →</a></p>
</section>

<section class="content-section">
<h2 id="development">Уже в ветке develop</h2>
<p>В ветке 0.4 появился пошаговый сценарий оценки и более наглядные офлайн-отчёты в HTML. Выбранные записи CVE, CWE и EPSS дополняют сведения о найденной проблеме. FuzzyRoutines даёт пятиуровневую интерпретацию оценки CVSS, а исходный балл виден в отчёте.</p>
<p>Добавились собственные веб-проверки и офлайн-импорт перечней компонентов в формате CycloneDX (SBOM), отчётов SARIF и журналов syslog. Первые инструменты анализа графа позволяют исследовать отдельные пути и сравнивать их состояние по сохранённым данным.</p>
<p><a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/CHANGELOG.md">История изменений develop →</a></p>
</section>

<section class="content-section">
<h2 id="use-cases">Для каких задач нужен 1337</h2>
<div class="grid">
<article class="card">
<h3>AppSec и пентест</h3>
<p>Проверьте согласованный сервис и передайте разработчикам доказательства по обнаруженной проблеме.</p>
</article>
<article class="card">
<h3>DevSecOps</h3>
<p>Сохраняйте отчёты из CI и возвращайтесь к результатам, на которых основано решение о выпуске.</p>
</article>
<article class="card">
<h3>Расследование инцидентов</h3>
<p>Разбирайте сохранённые артефакты и передавайте их вместе с первоисточниками другому аналитику.</p>
</article>
</div>
</section>

<section class="content-section">
<h2 id="ai-agents">Для инженеров, CI и ИИ-агентов</h2>
<p>С одним рабочим пространством можно работать из консоли, CI и через ИИ-агента с доступом к терминалу. Агент может предложить план и объяснить результат. 1337 применяет правила допуска и сохраняет запись о выполненных действиях. Для локальной работы аккаунт у поставщика ИИ не нужен.</p>
</section>

<section class="content-section">
<h2 id="roadmap">Что строим дальше</h2>
<div class="architecture-grid">
<article class="architecture-card">
<h3>Web Scanner NG и граф достижимости</h3>
<p>Расширяем собственные проверки веб-приложений и API. В графе можно будет увидеть, какие активы достижимы, какие пути атаки возможны и на каких данных основаны выводы.</p>
</article>
<article class="architecture-card">
<h3>Интерактивный анализ</h3>
<p>Многопанельный терминальный интерфейс и веб-интерфейс для разбора находок, сравнения результатов проверок и объяснения приоритетов риска.</p>
</article>
<article class="architecture-card">
<h3>Расследования и Purple Team</h3>
<p>Хронология инцидентов и рабочие представления для аналитиков и команд защиты, в которых видна связь наблюдений, срабатываний и доказательств.</p>
</article>
<article class="architecture-card">
<h3>Интеграции и ИИ</h3>
<p>API, SDK, интеграции с CI и доступ к 1337 через MCP с контролем по политикам и свободой выбора ИИ-модели и поставщика.</p>
</article>
</div>
<p><a href="https://github.com/Fuzzy-Technologies/1337/milestones">Открытый план разработки →</a></p>
</section>

<section class="content-section">
<h2 id="get-started">Попробуйте 1337 на своём компьютере</h2>
<p>Быстрый старт покажет, как запустить локальное демо, сохранить доказательства и открыть готовый отчёт офлайн. Инструкции на английском.</p>
<div class="links">
<a class="primary-action" href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/QUICKSTART.md">Быстрый старт</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/AGENT_QUICKSTART.md">Для ИИ-агентов</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/v0.3.0/docs/CI_QUICKSTART.md">Для CI</a>
</div>
</section>

<section class="content-section">
<h2 id="project">Открытое ядро Community</h2>
<p>Fuzzy Technologies разрабатывает 1337 открыто. Ядро Community распространяется по лицензии Apache 2.0.</p>
<div class="links">
<a href="https://github.com/Fuzzy-Technologies/1337">Код на GitHub</a>
<a href="https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/VISION.md">Видение проекта</a>
</div>
</section>

<footer class="site-footer">
<strong>1337 Security Workbench by Fuzzy Technologies</strong>
</footer>
