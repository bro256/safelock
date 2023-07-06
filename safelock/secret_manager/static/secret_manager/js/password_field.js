
function copyToClipboard() {
    var textToCopy = document.getElementById("password-field").value;
    navigator.clipboard.writeText(textToCopy)
      .then(function() {
        alert("Text copied to clipboard!");
      })
      .catch(function(error) {
        console.error("Error copying text to clipboard:", error);
      });
  }

function toggleTextVisibility() {
  var textField = document.getElementById("password-field");
  textField.type = textField.type === "password" ? "text" : "password";
}
function regeneratePassword() {
  var xhr = new XMLHttpRequest();
  xhr.open('GET', '/generate-password/', true);
  xhr.setRequestHeader('Content-Type', 'application/json');

  xhr.onload = function() {
    if (xhr.status === 200) {
      var response = JSON.parse(xhr.responseText);
      // Update the password field with the new password
      document.getElementById('password-field').value = response.password;
    }
    else {
      console.error('Error:', xhr.status);
    }
  };

  xhr.onerror = function() {
    console.error('Request failed.');
  };

  xhr.send();
}

window.addEventListener("DOMContentLoaded", function() {
  // Hide the text field on page load
  document.getElementById("password-field").type = "password";
});

