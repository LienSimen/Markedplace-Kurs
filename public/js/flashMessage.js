document.addEventListener("DOMContentLoaded", function () {
  setTimeout(function () {
    var flashMessage = document.getElementById("flash-message");
    if (flashMessage) {
      // Add 'hidden' class to trigger the translate animation
      flashMessage.classList.add("hidden");

      // Wait for the transition to finish before removing the element
      flashMessage.addEventListener("transitionend", function () {
        flashMessage.remove();
      });
    }
  }, 3000); // Display for 3 seconds
});
