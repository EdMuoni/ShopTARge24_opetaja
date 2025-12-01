namespace ShopTARge24.Models.Email
{
    public class EmailViewModel
    {
        public string To { get; set; } = string.Empty;
        public string? Subject { get; set; }
        public string? Body { get; set; }
        public IFormFileCollection? Attachment { get; set; }
    }
}
