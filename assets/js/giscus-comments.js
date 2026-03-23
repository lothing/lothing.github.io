(function () {
  function renderMessage(root, message) {
    var box = document.createElement("p");
    box.innerHTML = "<em>" + message + "</em>";
    root.replaceChildren(box);
  }

  function mountGiscus(root, config) {
    var script = document.createElement("script");
    script.src = "https://giscus.app/client.js";
    script.async = true;
    script.crossOrigin = "anonymous";
    script.setAttribute("data-repo", config.repo);
    script.setAttribute("data-repo-id", config.repoId);
    script.setAttribute("data-category", config.category);
    script.setAttribute("data-category-id", config.categoryId);
    script.setAttribute("data-mapping", config.mapping);
    script.setAttribute("data-strict", config.strict);
    script.setAttribute("data-reactions-enabled", config.reactionsEnabled);
    script.setAttribute("data-emit-metadata", config.emitMetadata);
    script.setAttribute("data-input-position", config.inputPosition);
    script.setAttribute("data-theme", config.theme);
    script.setAttribute("data-lang", config.lang);
    root.replaceChildren(script);
  }

  function init() {
    var roots = document.querySelectorAll("[data-comments-root]");
    if (!roots.length) {
      return;
    }

    var config = window.LOTHING_GISCUS_CONFIG || {};
    var ready = Boolean(
      config.enabled &&
      config.repo &&
      config.repoId &&
      config.category &&
      config.categoryId
    );

    roots.forEach(function (root) {
      if (!ready) {
        renderMessage(root, "评论功能暂不可用。");
        return;
      }

      mountGiscus(root, config);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
