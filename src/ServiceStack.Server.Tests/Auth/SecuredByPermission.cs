namespace ServiceStack.Server.Tests.Auth
{
    [Route("/secured-by-permission")]
    public class SecuredByPermission : IReturn<SecuredResponse>
    {
        public string Name { get; set; }
    }
}