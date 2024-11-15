document.addEventListener("DOMContentLoaded", function () {
  setTimeout(function () {
    var flashMessage = document.getElementById("flash-message");
    if (flashMessage) {
      flashMessage.classList.add("fade-out");
      setTimeout(function () {
        flashMessage.style.display = "none";
      }, 1000);
    }
  }, 3000);
});
