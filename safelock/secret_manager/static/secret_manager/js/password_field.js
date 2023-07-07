function copyToClipboard() {
    var textToCopy = document.getElementById("password-field").value;
    navigator.clipboard.writeText(textToCopy)
      .then(function() {
        alert("Password copied to clipboard!");
      })
      .catch(function(error) {
        console.error("Error copying to clipboard:", error);
      });
  }

function toggleTextVisibility() {
  var textField = document.getElementById("password-field");
  textField.type = textField.type === "password" ? "text" : "password";
}

async function generatePassword() { // Asynchronous function
  console.log("Generate Password button clicked"); // Debug

  try {
    // Await keyword is used to wait for the fetch() function to complete and return the response
    const response = await fetch('/generate-password/');
    // Wait for the response.json() method to parse the response body as JSON
    const data = await response.json();
    console.log("Response received:", data); // Debug
    // Update the password field with the new password
    document.getElementById('password-field').value = data.password; // Update the password field
    // Calculate and show the password strength
    showPasswordStrength();
  } catch (error) {
    console.error('Error:', error);
  }
}


function showPasswordStrength() {
  var passwordInput = document.getElementById("password-field");
  var strengthIndicator = document.getElementById("password-strength");

  var password = passwordInput.value;
  var strength = calculatePasswordStrength(password);

  // Update the strength indicator element with the password strength level
  strengthIndicator.textContent = strength;
}

function calculatePasswordStrength(password) {
  var score = 0;
  if (password.length >= 8) {
    score += 1;
  }
  if (/[a-z]/.test(password)) {
    score += 1;
  }
  if (/[A-Z]/.test(password)) {
    score += 1;
  }
  if (/\d/.test(password)) {
    score += 1;
  }
  if (/[!@#$%^&*()\-_=+[{\]}\\|;:'",<.>/?]/.test(password)) {
    score += 1;
  }
  // Return the password strength level
  if (score <= 1) {
    return "Weak";
  } else if (score <= 3) {
    return "Medium";
  } else {
    return "Strong";
  }
}

document.getElementById("password-field").addEventListener("input", showPasswordStrength);

window.addEventListener("DOMContentLoaded", function() {
  // Hide the text field on page load
  document.getElementById("password-field").type = "password";
  // Show password strength when the page is loaded
  showPasswordStrength();
});
