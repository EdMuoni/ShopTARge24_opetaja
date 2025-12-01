using ShopTARge24.Core.Dto;

namespace ShopTARge24.Core.ServiceInterface
{
    public interface IEmailServices
    {
        void SendEmail(Dto.EmailDto dto);
    }
}
