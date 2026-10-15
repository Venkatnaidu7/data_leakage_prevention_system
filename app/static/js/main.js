/* DLP Platform Client-Side Interactions */

document.addEventListener("DOMContentLoaded", function () {
  // Confirmation handler for destructive actions
  const confirmActions = document.querySelectorAll("[data-confirm]");
  confirmActions.forEach(function (element) {
    element.addEventListener("click", function (e) {
      const message = element.getAttribute("data-confirm") || "Are you sure you want to perform this action?";
      if (!window.confirm(message)) {
        e.preventDefault();
      }
    });
  });

  // Tab switching logic for Scanner (File vs Text)
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      const targetTab = button.getAttribute("data-tab");
      
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.style.display = "none");

      button.classList.add("active");
      const activeContent = document.getElementById(targetTab);
      if (activeContent) {
        activeContent.style.display = "block";
      }

      const modeInput = document.getElementById("scan_mode_input");
      if (modeInput) {
        modeInput.value = targetTab === "text-scan" ? "text" : "file";
      }
    });
  });
});
