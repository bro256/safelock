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

// async function generatePassword() { // Asynchronous function
//   console.log("Generate Password button clicked"); // Debug

//   try {
//     // Await keyword is used to wait for the fetch() function to complete and return the response
//     const response = await fetch('/generate-password/');
//     // Wait for the response.json() method to parse the response body as JSON
//     const data = await response.json();
//     console.log("Response received:", data); // Debug
//     // Update the password field with the new password
//     document.getElementById('password-field').value = data.password; // Update the password field
//     // Calculate and show the password strength
//     showPasswordStrength();
//   } catch (error) {
//     console.error('Error:', error);
//   }
// }

// async function generatePassword(length = 16, includeSymbols = true) { // Asynchronous function
//   console.log("Generate Password button clicked"); // Debug

//   try {
//     // Await keyword is used to wait for the fetch() function to complete and return the response
//     const url = `/generate-password/?length=${encodeURIComponent(length)}&symbols=${encodeURIComponent(includeSymbols)}`;
//     const response = await fetch(url);
//     // Wait for the response.json() method to parse the response body as JSON
//     const data = await response.json()
//     console.log("Response received:", data); // Debug
//     // Update the password field with the new password
//     const generatedPassword = data.password;
//     // Calculate and show the password strength
//     showPasswordStrength();

//     document.getElementById('password-field').value = generatedPassword; // Update the password field
//     // Calculate and show the password strength
//     showPasswordStrength();
//   } catch (error) {
//     console.error('Error:', error);
//   }
// }

async function generatePassword(length = 16, letters = true, numbers = true, symbols = true) {
  console.log("Generate Password button clicked"); // Debug

  try {
    // Prepare the URL with query parameters for the server endpoint
    const url = `/generate-password/?length=${encodeURIComponent(length)}&letters=${encodeURIComponent(letters)}&numbers=${encodeURIComponent(numbers)}&symbols=${encodeURIComponent(symbols)}`;

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
  if (password.length >= 12) {
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
  if (score == 0) {
    return "";
  } else if (score == 1) {
    return "Weak";
  } else if (score <= 3) {
    return "Moderate";
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

document.getElementById('generate-button').addEventListener('click', function() {
  const length = document.getElementById('length').value;
  const letters = true;
  const numbers = document.getElementById('numbers').checked;
  const symbols = document.getElementById('symbols').checked;

  generatePassword(length, letters, numbers, symbols);
});
