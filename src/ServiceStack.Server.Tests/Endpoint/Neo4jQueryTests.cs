using Funq;

namespace ServiceStack.Server.Tests.Endpoint
{
    public class Neo4jAuthRepositoryQueryTests : AuthRepositoryQueryTestsBase
    {
        public override void ConfigureAuthRepo(Container container) => 
            new Neo4jAuthRepositoryTests().ConfigureAuthRepo(container);
    }
}