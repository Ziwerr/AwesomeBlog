namespace AwesomeBlog.Api.Settings
{
    public class JwtSettings
    {
        public string ValidIssuer { get; set; } = "https://localhost:5001";
        public string ValidAudience { get; set; } = "https://localhost:5001";
        public string Secret { get; set; } = "49B79CB6-EB85-4DF2-941B-A2D1178C90BE";
        public int LifetimeInSeconds { get; set; } = 3600;

    }
}