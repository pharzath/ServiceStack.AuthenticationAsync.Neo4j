using Neo4j.Driver;
using ServiceStack.Auth;
using ServiceStack.Authentication.Neo4j;

namespace ServiceStack.Server.Tests.Auth
{
    public class Neo4jAuthRepoStatelessAuthTests : StatelessAuthTests
    {
        protected override ServiceStackHost CreateAppHost()
        {
            var driver = GraphDatabase.Driver("bolt://localhost:7687");
            new Neo4jAuthRepository(driver).Clear();

            return new AppHost
            {
                Use = container => container.Register<IAuthRepository>(c => new Neo4jAuthRepository(driver))
            };
        }
    }
}