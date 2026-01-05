using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ShopTARge24.Core.Domain;
using ShopTARge24.Core.Dto;
using ShopTARge24.Core.ServiceInterface;
using ShopTARge24.Models;
using ShopTARge24.Models.Accounts;
using System.Diagnostics;
using System.Security.Claims; // Add this using directive

namespace ShopTARge24.Controllers
{
    // This controller handles everything related to user accounts:
    // signing up, logging in, password resets, and Google login
    public class AccountsController : Controller
    {
        // These services help us manage users and their login sessions
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailServices _emailServices;

        // When this controller is created, ASP.NET automatically gives us these services
        public AccountsController
            (
                UserManager<ApplicationUser> userManager,
                SignInManager<ApplicationUser> signInManager,
                IEmailServices emailServices
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailServices = emailServices;
        }

        // Show the registration page
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        // Handle the registration form when someone submits it
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Register(RegisterViewModel vm)
        {
            // Only proceed if all the form fields are filled in correctly
            if (ModelState.IsValid)
            {
                // Create a new user with the info from the form
                var user = new ApplicationUser
                {
                    UserName = vm.Email,
                    Name = vm.Name,
                    Email = vm.Email,
                    City = vm.City,
                };

                // Try to save the new user to the database
                var result = await _userManager.CreateAsync(user, vm.Password);

                if (result.Succeeded)
                {
                    // Create a special token for email verification
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    // Build the link they'll click in their email
                    var confirmationLink = Url.Action("ConfirmEmail", "Accounts", new { userId = user.Id, token = token }, Request.Scheme);

                    // Set up the confirmation email
                    EmailTokenDto newsignup = new();
                    newsignup.Token = token;
                    newsignup.Body = $"Please registrate your account by: <a href=\"{confirmationLink}\">clicking here</a>";
                    newsignup.Subject = "CRUD registration";
                    newsignup.To = user.Email;

                    // If an admin is creating this account, send them back to the user list
                    if (_signInManager.IsSignedIn(User) && User.IsInRole("Admin"))
                    {
                        return RedirectToAction("ListUsers", "Administrations");
                    }

                    // Send the confirmation email
                    _emailServices.SendEmailToken(newsignup, token);

                    // Show a success message
                    List<string> errordatas =
                        [
                        "Area", "Accounts",
                        "Issue", "Success",
                        "StatusMessage", "Registration Successs",
                        "ActedOn", $"{vm.Email}",
                        "CreatedAccountData", $"{vm.Email}\n{vm.City}\n[password hidden]\n[password hidden]"
                        ];
                    ViewBag.ErrorDatas = errordatas;
                    ViewBag.ErrorTitle = "You have successfully registered";
                    ViewBag.ErrorMessage = "Before you can log in, please confirm email from the link" +
                        "\nwe have emailed to your email address.";
                    return View("ConfirmationEmailMessage");
                }

                // Something went wrong - show the user what happened
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }

            return View();
        }

        // When someone clicks the confirmation link in their email, this handles it
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            // Make sure we got both pieces of info we need
            if (userId == null || token == null)
            {
                return RedirectToAction("Index", "Home");
            }

            // Look up the user
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                ViewBag.ErrorMessage = $"The user with id of {userId} is not valid";
                return View("NotFound");
            }

            // Try to confirm their email
            var result = await _userManager.ConfirmEmailAsync(user, token);
            List<string> errordatas =
                        [
                        "Area", "Accounts",
                        "Issue", "Success",
                        "StatusMessage", "Registration Sucesss",
                        "ActedOn", $"{user.Email}",
                        "CreatedAccountData", $"{user.Email}\n{user.City}\n[password hidden]\n[password hidden]"
                        ];

            if (result.Succeeded)
            {
                // Email confirmed! They can now log in
                errordatas =
                        [
                        "Area", "Accounts",
                        "Issue", "Success",
                        "StatusMessage", "Registration Sucesss",
                        "ActedOn", $"{user.Email}",
                        "CreatedAccountData", $"{user.Email}\n{user.City}\n[password hidden]\n[password hidden]"
                        ];
                ViewBag.ErrorDatas = errordatas;
                return View();
            }

            // Something went wrong with the confirmation
            ViewBag.ErrorDatas = errordatas;
            ViewBag.ErrorTitle = "Email cannot be confirmed";
            ViewBag.ErrorMessage = $"The users email, with userid of {userId}, cannot be confirmed.";
            return View("Error", new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        // Show the login page
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string? returnUrl)
        {
            return View();
        }

        // Handle the login form submission
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl)
        {
            if (ModelState.IsValid)
            {
                // First, check if this user exists
                var user = await _userManager.FindByEmailAsync(model.Email);

                // If they haven't confirmed their email yet, don't let them in
                if (user != null && !user.EmailConfirmed &&
                    (await _userManager.CheckPasswordAsync(user, model.Password)))
                {
                    ModelState.AddModelError(string.Empty, "Email not confirmed yet");
                    return View(model);
                }

                // Try to log them in (last parameter enables lockout after failed attempts)
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, true);

                if (result.Succeeded)
                {
                    // Success! Send them where they were trying to go, or to the home page
                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }

                // Too many failed attempts - account is temporarily locked
                if (result.IsLockedOut)
                {
                    return View("AccountLocked");
                }

                // Wrong email or password
                ModelState.AddModelError("", "Invalid Login Attempt");
            }

            return View(model);
        }

        // Log the user out and send them to the home page
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        // Show the change password form
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        // Handle password change request
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Get the currently logged-in user
                var user = await _userManager.GetUserAsync(User);

                if (user == null)
                {
                    return RedirectToAction("Login");
                }

                // Try to change their password
                var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

                if (!result.Succeeded)
                {
                    // Show what went wrong (e.g., "current password is incorrect")
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }

                    return View();
                }

                // Password changed! Refresh their login session so they don't get logged out
                await _signInManager.RefreshSignInAsync(user);
                return View("ChangePasswordConfirmation");
            }

            return View(model);
        }

        // Show the "forgot password" form
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        // Handle forgot password request - sends a reset link via email
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                // Only send reset email if user exists and has confirmed their email
                // But always show the same message (security: don't reveal if account exists)
                if (user != null && await _userManager.IsEmailConfirmedAsync(user))
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var passwordResetLink = Url.Action("ResetPassword", "Accounts", new { email = model.Email, token = token }, Request.Scheme);

                    var emailDto = new EmailDto()
                    {
                        To = model.Email,
                        Subject = "Password Reset",
                        Body = $"Please reset your password by <a href=\"{passwordResetLink}\">clicking here</a>."
                    };

                    _emailServices.SendEmail(emailDto);

                    return View("ForgotPasswordConfirmation");
                }

                // Show same confirmation even if user doesn't exist (security measure)
                return View("ForgotPasswordConfirmation");
            }
            return View(model);
        }

        // Show the password reset form (user got here from email link)
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string token, string email)
        {
            if (token == null || email == null)
            {
                ModelState.AddModelError("", "Invalid password reset token");
            }
            return View();
        }

        // Handle the new password submission
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    // Try to reset with the token from their email
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (result.Succeeded)
                    {
                        // If they were locked out, unlock them now that they've reset their password
                        if (await _userManager.IsLockedOutAsync(user))
                        {
                            await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                        }

                        return View("ResetPasswordConfirmation");
                    }

                    // Show any errors (e.g., "password too weak")
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }

                    return View(model);
                }

                // User not found, but show success anyway (security measure)
                return View("ResetPasswordConfirmation");
            }

            return View(model);
        }

        // Start the Google login process - redirects user to Google's login page
        [HttpPost]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string? returnUrl)
        {
            // Tell Google where to send the user after they log in
            var redirectUrl = Url.Action("ExternalLoginCallback", "Accounts", new { ReturnUrl = returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            // This sends the user to Google
            return new ChallengeResult(provider, properties);
        }

        // Google sends the user back here after they've logged in
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl, string? remoteError)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            // Check if Google reported any problems
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");
                return View("Login");
            }

            // Get the login info Google sent us
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Error loading external login information.");
                return View("Login");
            }

            // Check if this Google account is already linked to a user in our system
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                // They've used Google login before - just let them in
                return LocalRedirect(returnUrl);
            }
            else
            {
                // First time using Google login - we need to create or link an account
                        var email = info.Principal.FindFirstValue(System.Security.Claims.ClaimTypes.Email);

                if (email != null)
                {
                    // Check if there's already an account with this email
                    var user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        // No account exists - create one using their Google info
                        user = new ApplicationUser
                        {
                            UserName = email,
                            Email = email,
                            Name = info.Principal.FindFirstValue(System.Security.Claims.ClaimTypes.Name) ?? email,
                            EmailConfirmed = true  // We trust Google verified their email
                        };

                        await _userManager.CreateAsync(user);
                    }

                    // Link their Google account to our user record
                    await _userManager.AddLoginAsync(user, info);

                    // Log them in
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnUrl);
                }

                // Google didn't give us their email - we can't proceed
                ViewBag.ErrorTitle = $"Email claim not received from: {info.LoginProvider}";
                ViewBag.ErrorMessage = "Please contact support.";
                return View("Error");
            }
        }
    }
}
