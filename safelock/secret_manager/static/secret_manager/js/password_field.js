function passwordToClipboard() {
    var textToCopy = document.getElementById("password-field").value;
    navigator.clipboard.writeText(textToCopy)
      .then(function() {
        alert("Password copied to clipboard!");
      })
      .catch(function(error) {
        console.error("Error copying to clipboard:", error);
      });
  }

  function usernameToClipboard() {
    var textToCopy = document.getElementById("username-field").value;
    navigator.clipboard.writeText(textToCopy)
      .then(function() {
        alert("Username copied to clipboard!");
      })
      .catch(function(error) {
        console.error("Error copying to clipboard:", error);
      });
  }

  function toggleTextVisibility() {
  var textField = document.getElementById("password-field");
  textField.type = textField.type === "password" ? "text" : "password";
}

async function generatePassword(length = 20, lowercase=true, uppercase=true, numbers = true, symbols = true) {
  console.log("Generate Password button clicked"); // Debug

  try {
    // Prepare the URL with query parameters for the server endpoint
    const url = `/generate-password/?length=${encodeURIComponent(length)}&lowercase=${encodeURIComponent(lowercase)}&uppercase=${encodeURIComponent(uppercase)}&numbers=${encodeURIComponent(numbers)}&symbols=${encodeURIComponent(symbols)}`;

    // Send a GET request to the server endpoint
    const response = await fetch(url);

    // Parse the response body as JSON
    const data = await response.json();
    console.log("Response received:", data); // Debug

    // Update the password field with the new password
    const generatedPassword = data.password;
    document.getElementById('password-field').value = generatedPassword;

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
  var patterns = {
    length: /[^\s\S]/,
    lowercase: /[a-z]/,
    uppercase: /[A-Z]/,
    digit: /\d/,
    specialChar: /[!@#$%^&*()\-_=+[{\]}\\|;:'",<.>/?]/
  };

  // Check each pattern and increment the score
  for (var pattern in patterns) {
    if (patterns[pattern].test(password)) {
      score++;
    }
  }

  if (score > 2 && password.length < 11) {
    score--;
  }
  
  if (score === 5 && password.length >= 16) {
    score++;
  }

  // Return the password strength level
  if (score === 0) {
    return "None";
  } else if (score === 1) {
    return "Weak";
  } else if (score === 2) {
    return "Moderate";
  } else if (score === 3) {
    return "Strong";
  } else if (score >= 4) {
    return "Very Strong";
  }
}

window.addEventListener("DOMContentLoaded", function() {
  // Hide the text field on page load
  document.getElementById("password-field").type = "password";
  // Show password strength when the page is loaded
  showPasswordStrength();
});

document.getElementById("password-field").addEventListener("input", showPasswordStrength);
document.getElementById('generate-button').addEventListener('click', function() {
  const length = document.getElementById('length').value;
  const lowercase = document.getElementById('lowercase').checked;
  const uppercase = document.getElementById('uppercase').checked;
  const numbers = document.getElementById('numbers').checked;
  const symbols = document.getElementById('symbols').checked;

  generatePassword(length, lowercase, uppercase, numbers, symbols);
});
