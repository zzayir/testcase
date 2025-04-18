let currentStep = 1;
let formData = {
  username: '',
  email: '',
  password: '',
  mobileNumber: '',
  nfcEnabled: false,
  nfcId: null
};
let fullNumber = '';

// Initialize the form
document.addEventListener('DOMContentLoaded', function() {
  showStep(currentStep);
  populateCountryCodes();
});

// Helper functions
function showError(elementId, message) {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.classList.remove('hidden');
}

function clearError(elementId) {
  const element = document.getElementById(elementId);
  element.textContent = '';
  element.classList.add('hidden');
}

// Show specific step with animation
function showStep(step) {
  console.log('Showing step', step);
  // Hide all steps
  document.querySelectorAll('.registration-step').forEach(el => {
    el.style.display = 'none';
  });
  
  // Show current step
  const currentStepEl = document.getElementById(`step${step}`);
  if (currentStepEl) {
    currentStepEl.style.display = 'block';
  }
  
  // Update progress bar
  document.querySelectorAll('.progress-step').forEach((el, index) => {
    if (index + 1 <= step) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });
}

// Populate country codes
function populateCountryCodes() {
  fetch('https://restcountries.com/v3.1/all')
    .then(res => {
      if (!res.ok) throw new Error('Failed to load country codes');
      return res.json();
    })
    .then(data => {
      const select = document.getElementById('countryCode');
      data.sort((a, b) => a.name.common.localeCompare(b.name.common)).forEach(country => {
        const root = country.idd?.root || '';
        const suffix = country.idd?.suffixes ? country.idd.suffixes[0] : '';
        const option = document.createElement('option');
        option.value = root + suffix;
        option.textContent = `${country.name.common} (${option.value})`;
        select.appendChild(option);
      });
    })
    .catch(err => {
      console.error('Error loading country codes:', err);
      // Fallback to some default options
      const select = document.getElementById('countryCode');
      const option = document.createElement('option');
      option.value = '+1';
      option.textContent = 'United States (+1)';
      select.appendChild(option);
    });
}

// Step 1 validation
function checkStep1() {
  clearError('message');
  
  formData.username = document.getElementById('username').value.trim();
  formData.email = document.getElementById('email').value.trim();
  formData.password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;

  if (!formData.username || !formData.email || !formData.password || !confirmPassword) {
    showError('message', 'All fields are required');
    return;
  }

  if (formData.password !== confirmPassword) {
    showError('message', 'Passwords do not match');
    return;
  }

  if (formData.password.length < 8) {
    showError('message', 'Password must be at least 8 characters');
    return;
  }

  // Check username availability
  fetch('/api/check-username', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: formData.username })
  })
  .then(res => {
    if (!res.ok) throw new Error('Username check failed');
    return res.json();
  })
  .then(data => {
    if (!data.available) {
      showError('message', 'Username not available');
    } else {
      currentStep = 2;
      showStep(currentStep);
    }
  })
  .catch(err => {
    console.error('Error checking username:', err);
    showError('message', 'Error checking username availability');
  });
}

// Step 2 functions
function sendOTP() {
  clearError('otpMsg');
  
  const mobile = document.getElementById('mobile').value.trim();
  const code = document.getElementById('countryCode').value;
  
  if (!mobile) {
    showError('otpMsg', 'Mobile number is required');
    return;
  }

  fullNumber = code + mobile;
  formData.mobileNumber = fullNumber;

  fetch('/api/send-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobileNumber: formData.mobileNumber })
  })
  .then(res => {
    if (!res.ok) throw new Error('Failed to send OTP');
    return res.json();
  })
  .then(() => {
    document.getElementById('otp-section').style.display = 'block';
    document.getElementById('otpMsg').textContent = 'OTP sent to your mobile number';
    document.getElementById('otpMsg').classList.remove('error');
    document.getElementById('otpMsg').classList.add('success');
  })
  .catch(err => {
    console.error('Error sending OTP:', err);
    showError('otpMsg', 'Failed to send OTP');
  });
}

function verifyOTP() {
  const otp = document.getElementById('otp').value.trim();
  
  if (!otp) {
    showError('otpMsg', 'OTP is required');
    return;
  }

  fetch('/api/verify-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mobileNumber: formData.mobileNumber, otp })
  })
  .then(res => {
    if (!res.ok) throw new Error('OTP verification failed');
    return res.json();
  })
  .then(data => {
    if (data.verified) {
      currentStep = 3;
      showStep(currentStep);
    } else {
      showError('otpMsg', 'Incorrect OTP');
    }
  })
  .catch(err => {
    console.error('Error verifying OTP:', err);
    showError('otpMsg', 'Error verifying OTP');
  });
}

function skipOTP() {
  const mobile = document.getElementById('mobile').value.trim();
  const code = document.getElementById('countryCode').value;
  
  if (!mobile) {
    showError('otpMsg', 'Mobile number is required');
    return;
  }

  fullNumber = code + mobile;
  formData.mobileNumber = fullNumber;
  currentStep = 3;
  showStep(currentStep);
}

// Step 3 functions
function handleNFCChoice(wantsNFC) {
  formData.nfcEnabled = wantsNFC;
  
  if (wantsNFC) {
    if ('NDEFReader' in window) {
      currentStep = 4;
      showStep(currentStep);
    } else {
      document.getElementById('nfc-status').textContent = 'NFC not supported in this browser';
      submitForm();
    }
  } else {
    submitForm();
  }
}

// Step 4 functions
async function scanNFC() {
  try {
    if (!('NDEFReader' in window)) {
      throw new Error('NFC not supported');
    }

    const ndef = new NDEFReader();
    document.getElementById('nfc-status').textContent = 'Ready to scan...';

    await ndef.scan();

    ndef.onreading = async (event) => {
      try {
        // Format serial number
        const serialBytes = new Uint8Array(event.serialNumber);
        const formattedSerial = Array.from(serialBytes)
          .map(b => b.toString(16).padStart(2, '0').toUpperCase())
          .join(':');
        
        // Generate unique expected text for each user
        const uniqueExpectedText = "ACCESS_" + 
          Math.random().toString(36).substring(2, 8).toUpperCase() + 
          "_GRANTED";
        
        const aesKey = generateRandomHex(32);
        const encryptedText = await encryptText(uniqueExpectedText, aesKey);

        // Write to NFC tag
        const encoder = new TextEncoder();
        await ndef.write({
          records: [{
            recordType: "text",
            data: encoder.encode(encryptedText),
            lang: "en"
          }]
        });
        
        // Store NFC data in formData
        formData.nfcId = formattedSerial;
        formData.authData = {
          aesKey,
          expectedText: uniqueExpectedText,
          allowedSerial: formattedSerial,
          encryptedText
        };

        document.getElementById('nfc-status').textContent = 
          `NFC registered successfully! Serial: ${formattedSerial}`;
        
        submitForm();
      } catch (err) {
        console.error("NFC registration error:", err);
        document.getElementById('nfc-status').textContent = 'Error: ' + err.message;
      }
    };

    ndef.onerror = (err) => {
      console.error("NFC error:", err);
      document.getElementById('nfc-status').textContent = 'NFC error: ' + err.message;
    };
  } catch (err) {
    console.error("NFC setup error:", err);
    document.getElementById('nfc-status').textContent = 'NFC error: ' + err.message;
  }
}

// Form submission
function submitForm() {
    // Show loading state
    currentStep = 4; // Changed to go to step 4 (final step) directly
    showStep(currentStep);
    
    const finalMessage = document.getElementById('final-message');
    const dashboardBtn = document.getElementById('dashboard-btn');
    
    finalMessage.textContent = 'Creating your account...';
    dashboardBtn.style.display = 'none'; // Hide button until registration completes
  
    // Prepare data for submission
    const submissionData = {
      username: formData.username,
      email: formData.email,
      password: formData.password,
      mobileNumber: formData.mobileNumber
    };
  
    // Include NFC data if enabled
    if (formData.nfcEnabled && formData.authData) {
      submissionData.authData = formData.authData;
    }
  
    // Submit data to server
    fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submissionData)
    })
    .then(res => {
      if (!res.ok) throw new Error('Registration failed');
      return res.json();
    })
    .then(data => {
      finalMessage.textContent = 'Your account has been successfully created!' + 
        (formData.nfcEnabled ? ' NFC authentication is enabled.' : '');
      finalMessage.classList.remove('error');
      finalMessage.classList.add('success');
      
      // Show dashboard button after successful registration
      dashboardBtn.style.display = 'block';
    })
    .catch(err => {
      console.error('Error during registration:', err);
      finalMessage.textContent = 'Error during registration: ' + err.message;
      finalMessage.classList.remove('success');
      finalMessage.classList.add('error');
      
      // Show dashboard button even on error (user might want to try again)
      dashboardBtn.style.display = 'block';
    });
  }
  
  // Employee Dashboard Redirection
  function goToDashboard() {
    window.location.href = 'employee.html';
  }

function generateRandomHex(len) {
  return Array.from(crypto.getRandomValues(new Uint8Array(len)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function encryptText(text, hexKey) {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      new Uint8Array(hexKey.match(/.{1,2}/g).map(byte => parseInt(byte, 16))),
      'AES-CBC',
      false,
      ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      new TextEncoder().encode(text)
    );
    return btoa([...iv, ...new Uint8Array(encrypted)].map(b => String.fromCharCode(b)).join(''));
  } catch (err) {
    console.error("Encryption error:", err);
    throw err;
  }
}

// Back navigation functions
function backToStep1() {
  currentStep = 1;
  showStep(currentStep);
}

function backToStep2() {
  currentStep = 2;
  showStep(currentStep);
}

function backToStep3() {
  currentStep = 3;
  showStep(currentStep);
}
