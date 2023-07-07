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
  } catch (error) {
    console.error('Error:', error);
  }
}

window.addEventListener("DOMContentLoaded", function() {
  // Hide the text field on page load
  document.getElementById("password-field").type = "password";
});
