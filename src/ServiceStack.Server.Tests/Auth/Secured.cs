namespace ServiceStack.Server.Tests.Auth
{
    [Route("/secured")]
    public class Secured : IReturn<SecuredResponse>
    {
        public string Name { get; set; }
    }
}
