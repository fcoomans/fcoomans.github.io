---
layout: single
# toc: true
# toc_sticky: true
permalink: /reports/index.html
---

<div>  
  <h1 id="page-title" class="page__title">HTB Machine Write-ups</h1>
  <div class="entries-list">

{% assign machines = site.htb-machines | sort: "date" | reverse %}
{% for machine in machines %}

    <div class="list__item">
      <article class="archive__item" itemscope itemtype="https://schema.org/CreativeWork">
      <h2 id="{{ machine.name }}" class="archive__item-title" itemprop="headline"><a href="{{ machine.url | relative_url }}" rel="permalink">{{ machine.name }}</a></h2>
    
      <p class="page__meta">
        <span class="page__meta-date">
          <i class="far fa-calendar-alt" aria-hidden="true"></i>
          <time datetime="{{ machine.date | date_to_xmlschema }}">{{ machine.date | date: "%B %d, %Y" | default: "N/A" }}</time>
        </span>

        <span class="page__meta-sep"></span>

        <span class="page__meta-readtime">
          <i class="far fa-clock" aria-hidden="true"></i>
          {% assign words_per_minute = site.words_per_minute | default: 200 %}
          {% assign words = machine.content | strip_html | number_of_words %}
          {% assign minutes = words | plus: words_per_minute | minus: 1 | divided_by: words_per_minute %}
          {% if words < words_per_minute %}less than 1 minute read
          {% elsif words == words_per_minute %}1 minute read
          {% else %}{{ minutes }} minute read
          {% endif %}
        </span>
      </p>
     
      <p class="writeup-meta">
        <strong>OS</strong>: {{ machine.os | default: "N/A" }}<br>
        <strong>Difficulty</strong>: {{ machine.difficulty | default: "N/A" }}<br>
        <strong>Skills</strong>: {{ machine.skills | default: "N/A" }}<br>
        <strong>Tools</strong>: {{ machine.tools | default: "N/A" }}
      </p>
 
      <p class="archive__item-excerpt" itemprop="description">{{ machine.content | split: '<h2' | slice: 1 | split: '</h2>' | last | split: '<h2' | first | replace: '\n', ' ' | strip | strip_html | replace: '`', '' | replace: '<code>', '' | replace: '</code>', '' | default: 'No summary available' | truncate: 250 }}
      </p>
      
      </article>
    </div>
{% endfor %}
  </div>
</div>
