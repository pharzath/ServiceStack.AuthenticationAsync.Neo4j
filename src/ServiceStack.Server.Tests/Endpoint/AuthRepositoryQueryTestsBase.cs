using System;
using Funq;
using NUnit.Framework;
using ServiceStack.Auth;
using ServiceStack.Testing;

namespace ServiceStack.Server.Tests.Endpoint
{
    [TestFixture]
    public abstract class AuthRepositoryQueryTestsBase
    {
        protected ServiceStackHost appHost;

        public abstract void ConfigureAuthRepo(Container container); 
        
        [OneTimeSetUp]
        public void TestFixtureSetUp()
        {
            appHost = new BasicAppHost(typeof(AuthRepositoryQueryTestsBase).Assembly) 
            {
                ConfigureAppHost = host =>
                {
                    host.Plugins.Add(new AuthFeature(() => new AuthUserSession(), new IAuthProvider[] {
                        new CredentialsAuthProvider(), 
                    })
                    {
                        IncludeRegistrationService = true,
                    });
                    
                    host.Plugins.Add(new SharpPagesFeature());
                },
                ConfigureContainer = container => {
                    
                    ConfigureAuthRepo(container);
                    
                    var authRepo = container.Resolve<IAuthRepository>();
                    if (authRepo is IClearable clearable)
                    {
                        try { clearable.Clear(); } catch {}
                    }

                    authRepo.InitSchema();
                    
                    SeedData(authRepo);
                }
            }.Init();
        }

        [OneTimeTearDown]
        public void OneTimeTearDown() => appHost.Dispose(); 

        void SeedData(IAuthRepository authRepo)
        {
            var newUser = authRepo.CreateUserAuth(new AppUser
            {
                Id = 1,
                DisplayName = "Test User",
                Email = "user@gmail.com",
                FirstName = "Test",
                LastName = "User",
            }, "p@55wOrd");

            newUser = authRepo.CreateUserAuth(new AppUser
            {
                Id = 2,
                DisplayName = "Test Manager",
                Email = "manager@gmail.com",
                FirstName = "Test",
                LastName = "Manager",
            }, "p@55wOrd");
            authRepo.AssignRoles(newUser, roles:new[]{ "Manager" });

            newUser = authRepo.CreateUserAuth(new AppUser
            {
                Id = 3,
                DisplayName = "Admin User",
                Email = "admin@gmail.com",
                FirstName = "Admin",
                LastName = "Super User",
            }, "p@55wOrd");
            authRepo.AssignRoles(newUser, roles:new[]{ "Admin" });
        }

        [Test]
        public void Can_fetch_roles_and_permissions()
        {
            var authRepo = appHost.GetAuthRepository();
            using (authRepo as IDisposable)
            {
                if (authRepo is IManageRoles manageRoles)
                {
                    manageRoles.GetRolesAndPermissions("3", 
                        out var roles, out var permissions);
                    
                    Assert.That(roles, Is.EquivalentTo(new[] { "Admin" }));
                }
            }
        }
    }
}