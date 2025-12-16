using Microsoft.Extensions.Configuration;
using MimeKit;
using ShopTARge24.Core.Dto;
using MailKit.Net.Smtp;
using ShopTARge24.Core.ServiceInterface;


namespace ShopTARge24.ApplicationServices.Services
{
    public class EmailServices : IEmailServices
    {
        private readonly IConfiguration _config;

        // Constructor to inject the configuration settings
        public EmailServices
            (
                IConfiguration config
            )
        {
            _config = config;
        }

        // Method to send an email with optional attachments
        public void SendEmail(EmailDto dto)
        {
            var email = new MimeMessage();
            email.From.Add(MailboxAddress.Parse(_config.GetSection("EmailUserName").Value));
            email.To.Add(MailboxAddress.Parse(dto.To));
            email.Subject = dto.Subject;

            var builder = new BodyBuilder
            {
                HtmlBody = dto.Body
            };

            //failide lisamine
            foreach (var file in dto.Attachment)
            {
                if (file.Length > 0 && file.Length < 10485760) //10MB
                {
                    using (var ms = new MemoryStream())
                    {
                        file.CopyTo(ms);
                        ms.Position = 0;
                        //var fileBytes = ms.ToArray();
                        //builder.Attachments.Add(file.FileName, fileBytes, ContentType.Parse(file.ContentType));
                        builder.Attachments.Add(file.FileName, ms.ToArray());
                    }
                }
            }
            email.Body = builder.ToMessageBody();
            using var smtp = new SmtpClient();

            smtp.Connect(_config.GetSection("EmailHost").Value, 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate(_config.GetSection("EmailUserName").Value, _config.GetSection("EmailPassword").Value);
            smtp.Send(email);
            smtp.Disconnect(true);

        }

        // Implement the missing interface method
        public void SendEmailToken(EmailTokenDto newsignup, string token)
        {
            SendEmailToToken(newsignup, token);
        }

        public void SendEmailToToken(EmailTokenDto dto, string token)
        {
            dto.Token = token;
            var email = new MimeMessage();

            // Hardcoded configuration values for demonstration purposes 
            _config.GetSection("EmailUserName").Value = "edgar.muoni@gmail.com";
            _config.GetSection("EmailHost").Value = "smtp.gmail.com";
            _config.GetSection("EmailPassword").Value = "kjoo hcsv tpsm njac";

            email.From.Add(MailboxAddress.Parse(_config.GetSection("EmailUserName").Value));
            // Set the sender's email address
            email.To.Add(MailboxAddress.Parse(dto.To)); // Set the recipient's email address
            email.Subject = dto.Subject;
            var builder = new BodyBuilder
            {
                HtmlBody = dto.Body
            };

            email.Body = builder.ToMessageBody();
            using var smtp = new SmtpClient();

            smtp.Connect(_config.GetSection("EmailHost").Value, 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate(_config.GetSection("EmailUserName").Value, _config.GetSection("EmailPassword").Value);
            smtp.Send(email);
            smtp.Disconnect(true);
        }
    }
}