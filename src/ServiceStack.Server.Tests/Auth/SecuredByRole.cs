namespace ServiceStack.Server.Tests.Auth
{
    [Route("/secured-by-role")]
    public class SecuredByRole : IReturn<SecuredResponse>
    {
        public string Name { get; set; }
    }
}