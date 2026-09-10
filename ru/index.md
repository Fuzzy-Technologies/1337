---
layout: default
lang: ru
title: 1337 Security Workbench
description: 1337 Security Workbench от Fuzzy Technologies — открытая рабочая среда ИБ и независимая от модели киберплатформа для людей и ИИ-агентов.
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
    <p class="eyebrow">Открытая рабочая среда ИБ · Киберплатформа, не привязанная к модели</p>
    <p class="hero-hook">Инструменты находят факты.<br><strong>1337 сохраняет состояние безопасности.</strong></p>
    <span class="status">Ранняя стадия · ядро Apache-2.0 · v0.1.8</span>
  </div>
  <div class="hero-secondary">
    <p>Открытая рабочая среда для хакеров, инженеров ИБ, исследователей и команд безопасности. Она превращает вывод специализированных инструментов в проверяемые доказательства и устойчивое состояние безопасности — основу для анализа достижимости и путей атаки.</p>
    <blockquote class="hero-quote"><strong>Модели рассуждают. 1337 хранит состояние, управляет выполнением и сохраняет доказательства.</strong></blockquote>
    <div class="links hero-actions">
      <a href="https://github.com/Fuzzy-Technologies/1337">Репозиторий GitHub</a>
      <a href="https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.1.8">Предварительный выпуск v0.1.8</a>
      <a href="https://github.com/Fuzzy-Technologies/1337/milestones">План разработки</a>
    </div>
  </div>
</section>

<section class="content-section">
  <h2>Сканирование — не самое сложное</h2>
  <div class="grid problem-grid">
    <section class="card">
      <span class="card-label">Разрозненные инструменты</span>
      <h3>Вывод инструмента — ещё не состояние безопасности</h3>
      <p>Nmap знает порты. Nuclei — шаблоны проверок. Браузер — текущую сессию. Отчёт — то, что было вчера. Цельную картину всё равно приходится собирать самому.</p>
    </section>
    <section class="card">
      <span class="card-label">ИИ нужен устойчивый контекст</span>
      <h3>Рассуждение — не память</h3>
      <p>Сильная модель умеет анализировать данные об уязвимостях и инфраструктуре. Но окно чата не заменяет модель активов, границы разрешённой проверки, хранилище доказательств и граф атак.</p>
    </section>
    <section class="card">
      <span class="card-label">Приоритизация</span>
      <h3>Критичность — ещё не путь атаки</h3>
      <p>Количество уязвимостей само по себе не показывает, что действительно достижимо, какие переходы складываются в цепочку и какая защитная мера разорвёт путь к важной цели.</p>
    </section>
  </div>
</section>

<section class="content-section">
  <h2>1337 начинается там, где инструмент закончил работу</h2>
  <div class="workbench-grid">
    <div class="flow-panel" aria-label="Поток данных 1337">
      <pre><code>Инструмент / Сканер
        ↓
   Доказательства
        ↓
 Объекты безопасности
        ↓
      Находки
        ↓
   Достижимость
        ↓
    Пути атаки
        ↓
 Следующее решение</code></pre>
    </div>
    <div class="workbench-copy">
      <p class="section-hook"><strong>1337 не заменяет набор инструментов. Это рабочая среда вокруг них.</strong></p>
      <p>Специализированные инструменты остаются специализированными. 1337 сохраняет их результаты как проверяемые доказательства, связывает их с устойчивыми объектами безопасности и делает полученное состояние пригодным для людей, автоматизации и будущих ИИ-агентов.</p>
      <p class="workbench-note">Полезная граница начинается там, где обычный инструмент заканчивает работу: результат уже получен, но состояние безопасности, достижимость, происхождение данных и следующее решение ещё не связаны между собой.</p>
    </div>
  </div>
</section>

<section class="content-section">
  <h2>Одно ядро — разные роли</h2>
  <div class="grid">
    <section class="card">
      <span class="card-label">Ручная работа</span>
      <h3>Хакеры и инженеры ИБ</h3>
      <p>Подключайте специализированные инструменты, сохраняйте доказательства и контекст, исследуйте значимые пути атаки — без необходимости каждый раз восстанавливать картину по истории терминала.</p>
    </section>
    <section class="card">
      <span class="card-label">Своя модель</span>
      <h3>Разработчики ИИ-систем для ИБ</h3>
      <p>Используйте структурированные объекты безопасности и типизированные возможности между заменяемой ИИ-моделью и реальными инструментами, не привязывая архитектуру к одному поставщику моделей.</p>
      <p class="card-hook">Подключайте свою модель. Рабочую киберсреду даёт 1337.</p>
    </section>
    <section class="card">
      <span class="card-label">Непрерывный контекст</span>
      <h3>Команды безопасности</h3>
      <p>Стройте управляемую картину: что изменилось, что стало достижимо, какие пути действительно важны и какая защитная мера даст наибольший эффект.</p>
    </section>
  </div>
</section>

<section class="content-section">
  <h2>Архитектура, которая приносит пользу</h2>
  <div class="architecture-grid">
    <section class="architecture-card"><h3>Модель объектов безопасности</h3><p>Единый язык для активов, сервисов, конечных точек, идентичностей, защитных мер, доказательств, находок, достижимости и путей атаки.</p></section>
    <section class="architecture-card"><h3>Фабрика возможностей</h3><p>Описывает требуемую операцию безопасности без жёсткой привязки процесса к конкретному сканеру или поставщику.</p></section>
    <section class="architecture-card"><h3>Область проверки и правила</h3><p>Явно задаёт границы разрешения, воздействия и выполнения вместо того, чтобы прятать их в запросах к модели или держать в памяти оператора.</p></section>
    <section class="architecture-card"><h3>Среда выполнения</h3><p>Запускает инструменты и встроенные возможности через контролируемый контур, а не выдаёт агенту неограниченный доступ к командной оболочке.</p></section>
    <section class="architecture-card"><h3>Доказательства и происхождение данных</h3><p>Связывает важные выводы с тем, что реально произошло: источником, областью проверки, временем, инструментом, исполнителем и подтверждающими материалами.</p></section>
    <section class="architecture-card"><h3>Достижимость и граф атак</h3><p>Помогает приоритизировать пути к значимым последствиям, а не считать количество уязвимостей или их критичность достаточной картиной риска.</p></section>
  </div>
  <p class="invariant"><strong>Модель можно заменить. Состояние безопасности — нет.</strong></p>
</section>

<section class="content-section">
  <h2>Куда мы идём</h2>
  <div class="roadmap-panel">
    <div class="roadmap-heading">
      <span class="status roadmap-status">M4 · планируемая воспроизводимая демонстрация</span>
      <a href="https://github.com/Fuzzy-Technologies/1337/issues/115">План демонстрации #115 →</a>
    </div>
    <p>Публичная демонстрация должна поднимать одну лабораторную среду из репозитория и показывать три проверяемых сценария поверх одной модели состояния безопасности 1337:</p>
    <div class="case-grid">
      <section class="case-card"><span class="card-label">Влияние на бизнес</span><p><strong>Интернет → Портал клиента → Идентичность → API биллинга → Бизнес-событие</strong></p></section>
      <section class="case-card"><span class="card-label">Идентичность и привилегии</span><p><strong>Интернет → Портал поддержки → Учётная запись → SSO/IAM → Панель администратора</strong></p></section>
      <section class="case-card"><span class="card-label">Цепочка поставки ПО</span><p><strong>Репозиторий → Задача CI → Исполнитель → Хранилище артефактов → Развёртывание → Рабочая среда</strong></p></section>
    </div>
    <blockquote><strong>Можно ли отсюда добраться до действительно важной цели, почему 1337 считает этот путь возможным и какая защитная мера его разорвёт?</strong></blockquote>
    <p class="quiet">Демонстрация M4 пока находится в плане и не является возможностью v0.1.8. Цель — лаборатория на Docker Compose, которую пользователь сможет поднять, просканировать, проверить, сбросить и независимо воспроизвести результат.</p>
    <p class="showcase-hook"><strong>Подними стенд. Просканируй сам. Докажи связь. Разорви путь. Сбрось лабораторию. Повтори.</strong></p>
  </div>
</section>

<section class="content-section">
  <h2>Доказательства вместо обещаний</h2>
  <div class="proof-grid">
    <section class="proof-card proof-now">
      <span class="card-label">Есть сегодня · v0.1.8</span>
      <h3>Воспроизводимая основа ранней версии</h3>
      <ul>
        <li>открытое ядро под Apache-2.0</li>
        <li>устанавливаемые команды запуска 1337 / 1337-dev</li>
        <li>основа центрального реестра команд</li>
        <li>изолированная синтетическая лаборатория из репозитория</li>
        <li>основа функциональных тестов на pytest</li>
        <li>публичные версионируемые контракты и архитектурная документация</li>
        <li>детерминированные проверки качества на нескольких платформах</li>
      </ul>
    </section>
    <section class="proof-card">
      <span class="card-label">В планах · отсутствует в v0.1.8</span>
      <h3>Что ещё предстоит сделать</h3>
      <ul>
        <li>интерактивная оболочка и рабочая среда</li>
        <li>адаптеры реальных сканеров</li>
        <li>процессы работы с находками и достижимостью</li>
        <li>интерфейс графа атак</li>
        <li>интерфейсы для ИИ-агентов</li>
        <li>корпоративные возможности</li>
      </ul>
    </section>
  </div>
  <p class="section-hook">Амбициозная архитектура полезна только тогда, когда превращается в воспроизводимое ПО с явными контрактами, тестами, доказательствами и честно обозначенным состоянием готовности.</p>
</section>

<section class="content-section">
  <h2>Материалы проекта</h2>
  <div class="links">
    <a href="https://github.com/Fuzzy-Technologies/1337#readme">README</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/VISION.md">Видение проекта</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/AI_AGENTS.md">Архитектура ИИ-агентов</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/docs/adr/0008-ai-native-cyber-execution-platform.md">ADR 0008 · Исполнение, состояние и доказательства в ИИ-архитектуре</a>
    <a href="https://github.com/Fuzzy-Technologies/1337/blob/master/SECURITY.md">Политика безопасности</a>
  </div>
</section>

<section class="content-section">
  <h2>Ответственное использование</h2>
  <p>1337 предназначен для защитной инженерии ИБ, разрешённых проверок, обучения, исследований, CTF и лабораторных сред, а также систем, которыми вы владеете или на проверку которых у вас есть явное разрешение.</p>
  <p>Не используйте проект для сканирования, проверки, эксплуатации уязвимостей или нарушения работы чужих систем без разрешения.</p>
</section>

<footer class="site-footer">
  <strong>1337 Security Workbench by Fuzzy Technologies</strong>
  <span>Технологии · Знания · Наука</span>
</footer>
