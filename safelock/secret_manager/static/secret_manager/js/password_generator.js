document.addEventListener('DOMContentLoaded', function() {
    var slider = document.getElementById('length');
    var output = document.querySelector('.form-range-output');

    slider.addEventListener('input', function() {
      output.textContent = this.value;
    });
  });
  