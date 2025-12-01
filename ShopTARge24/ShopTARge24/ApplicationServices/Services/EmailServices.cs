using Microsoft.Extensions.Configuration;
using MimeKit;
using ShopTARge24.Core.Dto;
using MailKit.Net.Smtp;


namespace ShopTARge24.ApplicationServices.Services
{
    public class EmailServices
    {
        private readonly IConfiguration _config;

        public EmailServices
            (
                IConfiguration config
            )
        {
            _config = config;
        }


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
            //kontrollib faili suurust ja siis saadab teele

            //tuleb teha foreach tsükkel, kus
            //läbib kõik dto.Attachment failid
            //ja lisab need emailile
            //kui failide arv või faili suurus on alla mingi piiri,
            //siis ei lisa faili
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
    }
}