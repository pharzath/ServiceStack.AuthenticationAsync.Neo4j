using Funq;
using Neo4j.Driver;
using ServiceStack.Auth;
using ServiceStack.Authentication.Neo4j;

namespace ServiceStack.Server.Tests.Endpoint
{
    public class Neo4jAuthRepositoryTests : AuthRepositoryTestsBase
    {
        public override void ConfigureAuthRepo(Container container)
        {
            var driver = GraphDatabase.Driver("bolt://localhost:7687");
            container.AddSingleton(driver);
            container.AddSingleton<IAuthRepository>(c =>
            {
                var repository = new Neo4jAuthRepository(c.Resolve<IDriver>());
                repository.Clear();
                return repository;
            });
        }
    }
}