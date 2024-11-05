using Microsoft.OpenApi.Writers;

namespace TestKeycloak.Dtos
{
    public class TokenRequestDto
    {
        public string username { get; set; }
        public string password { get; set; }

        public string scope { get; set; }
    }
}
