---
layout: page
permalink: /categories/
title: Categories
---

<script>

document.addEventListener("DOMContentLoaded", function() {
  const categories = document.querySelectorAll(".archive-group");

  categories.forEach(category => {
    const postsList = category.querySelector(".posts-list");
    const slideHandle = category.querySelector(".slide-handle");
    const posts = postsList.querySelectorAll(".archive-item");

    const visiblePostsLimit = 5; // Límite de posts visibles
    const postCount = posts.length;

    // Si hay más posts que los visibles, mostramos el deslizador
    if (postCount > visiblePostsLimit) {
      slideHandle.style.display = "block"; // Mostrar deslizador
    }

    // Configuramos el comportamiento del deslizador
    slideHandle.addEventListener("mousedown", function(e) {
      const startY = e.clientY;
      const startScrollTop = postsList.scrollTop;

      function onMouseMove(e) {
        const deltaY = e.clientY - startY;
        const maxScroll = postsList.scrollHeight - postsList.clientHeight;
        postsList.scrollTop = startScrollTop + deltaY;

        // Limitar el desplazamiento al tamaño máximo
        if (postsList.scrollTop < 0) postsList.scrollTop = 0;
        if (postsList.scrollTop > maxScroll) postsList.scrollTop = maxScroll;
      }

      function onMouseUp() {
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
      }

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
    });
  });
});

</script>

<div id="archives">
  {% for category in site.categories %}
    <div class="archive-group">
      {% capture category_name %}{{ category | first }}{% endcapture %}
      <div id="{{ category_name | slugize }}"></div>

      <div class="uml-box">
        <div class="uml-header">
          {{ category_name }}
        </div>

        <div class="posts-list" id="posts-{{ category_name | slugize }}">
          {% for post in site.categories[category_name] %}
            <article class="archive-item">
              <h4><a href="{{ site.baseurl }}{{ post.url }}">
                {% if post.title and post.title != "" %}
                  {{ post.title }}
                {% else %}
                  {{ post.excerpt | strip_html }}
                {% endif %}
              </a></h4>
            </article>
          {% endfor %}
        </div>

      </div>
    </div>
  {% endfor %}
</div>




