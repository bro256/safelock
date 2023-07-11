// document.getElementById('generate-button').addEventListener('click', function() {
//     const length = document.getElementById('length').value;
//     const includeSymbols = document.getElementById('symbols').checked;

//     generatePassword(length, includeSymbols);
// });
document.addEventListener('DOMContentLoaded', function() {
    var slider = document.getElementById('length');
    var output = document.querySelector('.form-range-output');

    slider.addEventListener('input', function() {
      output.textContent = this.value;
    });
  });