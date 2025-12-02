using Microsoft.AspNetCore.SignalR;

namespace SignalRSample.Hubs
{
    public class UserHub : Hub
    {
        public static int TotalViews { get; set; } = 0;

        public async Task NewWindowLoaded()
        {
            TotalViews++;
            //Send update to all connected clients that total views have been updated
            await Clients.All.SendAsync("UpdateTotalViews", TotalViews);
        }
    }
}
