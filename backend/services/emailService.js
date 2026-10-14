import nodemailer from 'nodemailer';

/**
 * Creates and configures the Nodemailer transporter using environment variables.
 * Automatically handles common host misconceptions (e.g. email address in EMAIL_HOST).
 */
const createTransporter = () => {
  let host = process.env.EMAIL_HOST;
  const port = process.env.EMAIL_PORT ? parseInt(process.env.EMAIL_PORT, 10) : 587;
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASSWORD;

  // If host is an email address or contains gmail/yahoo/outlook, auto-normalize to standard SMTP host
  if (host) {
    const trimmedHost = host.trim().toLowerCase();
    if (trimmedHost.includes('@') || trimmedHost.includes('gmail.com')) {
      host = 'smtp.gmail.com';
    } else if (trimmedHost.includes('yahoo')) {
      host = 'smtp.mail.yahoo.com';
    } else if (trimmedHost.includes('outlook') || trimmedHost.includes('hotmail')) {
      host = 'smtp-mail.outlook.com';
    }
  }

  // If host or password not provided or using sample placeholders, fallback to console logging
  if (!host || !user || !pass || pass === 'your_email_app_password' || pass.trim() === '') {
    return null;
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465, // true for 465, false for other ports
    auth: {
      user,
      pass,
    },
    connectionTimeout: 6000,
    greetingTimeout: 6000,
    socketTimeout: 6000,
  });
};

/**
 * Send an Email Verification OTP to a newly registered user
 * @param {string} email - Destination email address
 * @param {string} otp - 6-digit one-time password
 * @param {string} name - Customer name
 */
export const sendVerificationOTP = async (email, otp, name = 'Customer') => {
  const transporter = createTransporter();
  const from = process.env.EMAIL_FROM || '"JR PRINTING WORKS" <no-reply@jrprinting.in>';

  const subject = `Your Verification Code for JR PRINTING WORKS: ${otp}`;
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #FAF9F5; margin: 0; padding: 24px; color: #1c1917; }
        .card { max-width: 500px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e7e5e4; padding: 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .logo { width: 48px; height: 48px; background: #f59e0b; color: #0c0a09; font-size: 22px; font-weight: 900; line-height: 48px; text-align: center; border-radius: 12px; margin-bottom: 16px; }
        .title { font-size: 20px; font-weight: 800; margin: 0 0 8px 0; color: #0c0a09; text-transform: uppercase; letter-spacing: -0.5px; }
        .sub { font-size: 13px; color: #78716c; margin-bottom: 24px; }
        .otp-box { background: #f5f5f4; border: 2px dashed #d6d3d1; border-radius: 12px; padding: 18px; text-align: center; margin: 24px 0; }
        .otp-code { font-family: monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #0c0a09; }
        .info { font-size: 13px; color: #57534e; line-height: 1.6; }
        .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #f5f5f4; font-size: 11px; color: #a8a29e; text-align: center; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">JR</div>
        <h1 class="title">JR PRINTING WORKS</h1>
        <div class="sub">Pro. Shaikh Sameer • Custom Printing Studio</div>
        
        <p class="info">Hello <strong>${name}</strong>,</p>
        <p class="info">Thank you for registering with JR PRINTING WORKS. Please use the verification code below to activate your account:</p>
        
        <div class="otp-box">
          <div class="otp-code">${otp}</div>
        </div>
        
        <p class="info">⏱️ This code is valid for <strong>10 minutes</strong>. For your security, do not share this OTP with anyone.</p>
        <p class="info">If you did not request this registration, please disregard this email.</p>
        
        <div class="footer">
          JR PRINTING WORKS • Contact: +91 7888162822 / 7888162824<br>
          Serving custom T-shirts, Mugs, Pillows, Bottles, Frames & Covers
        </div>
      </div>
    </body>
    </html>
  `;

  if (!transporter) {
    console.log(`\n======================================================`);
    console.log(`📧 [EMAIL SERVICE] Email Verification OTP`);
    console.log(`➡️  To: ${email} (${name})`);
    console.log(`🔑  OTP Code: ${otp}`);
    console.log(`⏱️  Expires in: 10 minutes`);
    console.log(`======================================================\n`);
    return { success: true, mode: 'dev', messageId: `dev-verify-${Date.now()}` };
  }

  try {
    const info = await transporter.sendMail({
      from,
      to: email,
      subject,
      html,
      text: `Hello ${name},\n\nYour JR PRINTING WORKS verification code is: ${otp}\nValid for 10 minutes.\nDo not share this code with anyone.`,
    });
    console.log(`✅ Verification email sent to ${email}: ${info.messageId}`);
    return { success: true, mode: 'smtp', messageId: info.messageId };
  } catch (error) {
    console.warn(`⚠️ Notice: SMTP delivery to ${email} failed (${error.message}).`);
    console.log(`\n======================================================`);
    console.log(`📧 [FALLBACK OTP CODE] For: ${email}`);
    console.log(`🔑  OTP Code: ${otp}`);
    console.log(`⏱️  Expires in: 10 minutes`);
    console.log(`======================================================\n`);
    return { success: true, mode: 'fallback', error: error.message };
  }
};

/**
 * Send a Password Reset OTP to a user
 * @param {string} email - Destination email address
 * @param {string} otp - 6-digit one-time password
 * @param {string} name - Customer name
 */
export const sendPasswordResetOTP = async (email, otp, name = 'Valued Customer') => {
  const transporter = createTransporter();
  const from = process.env.EMAIL_FROM || '"JR PRINTING WORKS" <no-reply@jrprinting.in>';

  const subject = `Password Reset Code for JR PRINTING WORKS: ${otp}`;
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #FAF9F5; margin: 0; padding: 24px; color: #1c1917; }
        .card { max-width: 500px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e7e5e4; padding: 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        .logo { width: 48px; height: 48px; background: #f59e0b; color: #0c0a09; font-size: 22px; font-weight: 900; line-height: 48px; text-align: center; border-radius: 12px; margin-bottom: 16px; }
        .title { font-size: 20px; font-weight: 800; margin: 0 0 8px 0; color: #0c0a09; text-transform: uppercase; letter-spacing: -0.5px; }
        .sub { font-size: 13px; color: #78716c; margin-bottom: 24px; }
        .otp-box { background: #fef2f2; border: 2px dashed #fca5a5; border-radius: 12px; padding: 18px; text-align: center; margin: 24px 0; }
        .otp-code { font-family: monospace; font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #b91c1c; }
        .info { font-size: 13px; color: #57534e; line-height: 1.6; }
        .warning { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; border-radius: 4px; font-size: 12px; color: #92400e; margin: 16px 0; }
        .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid #f5f5f4; font-size: 11px; color: #a8a29e; text-align: center; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="logo">JR</div>
        <h1 class="title">JR PRINTING WORKS</h1>
        <div class="sub">Pro. Shaikh Sameer • Security Team</div>
        
        <p class="info">Hello <strong>${name}</strong>,</p>
        <p class="info">We received a request to reset the password for your JR PRINTING WORKS account. Use the authorization code below:</p>
        
        <div class="otp-box">
          <div class="otp-code">${otp}</div>
        </div>
        
        <p class="info">⏱️ This password reset code is valid for <strong>10 minutes</strong>.</p>
        
        <div class="warning">
          ⚠️ <strong>Security Notice:</strong> Never share this code with anyone. JR PRINTING WORKS staff will never ask for your password or reset OTP.
        </div>
        
        <p class="info">If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        
        <div class="footer">
          JR PRINTING WORKS • Contact: +91 7888162822 / 7888162824<br>
          Serving custom T-shirts, Mugs, Pillows, Bottles, Frames & Covers
        </div>
      </div>
    </body>
    </html>
  `;

  if (!transporter) {
    console.log(`\n======================================================`);
    console.log(`🔐 [EMAIL SERVICE] Password Reset OTP`);
    console.log(`➡️  To: ${email} (${name})`);
    console.log(`🔑  Reset OTP Code: ${otp}`);
    console.log(`⏱️  Expires in: 10 minutes`);
    console.log(`======================================================\n`);
    return { success: true, mode: 'dev', messageId: `dev-reset-${Date.now()}` };
  }

  try {
    const info = await transporter.sendMail({
      from,
      to: email,
      subject,
      html,
      text: `Hello ${name},\n\nYour password reset code for JR PRINTING WORKS is: ${otp}\nValid for 10 minutes.\nDo not share this code with anyone.`,
    });
    console.log(`✅ Password reset email sent to ${email}: ${info.messageId}`);
    return { success: true, mode: 'smtp', messageId: info.messageId };
  } catch (error) {
    console.warn(`⚠️ Notice: SMTP reset delivery to ${email} failed (${error.message}).`);
    console.log(`\n======================================================`);
    console.log(`🔐 [FALLBACK RESET OTP] For: ${email}`);
    console.log(`🔑  Reset OTP Code: ${otp}`);
    console.log(`⏱️  Expires in: 10 minutes`);
    console.log(`======================================================\n`);
    return { success: true, mode: 'fallback', error: error.message };
  }
};
