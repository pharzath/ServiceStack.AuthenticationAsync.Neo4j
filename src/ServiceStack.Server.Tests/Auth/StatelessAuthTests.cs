using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using ServiceStack.Auth;
using ServiceStack.Authentication.Neo4j;
using ServiceStack.Text;

namespace ServiceStack.Server.Tests.Auth
{
    public abstract class StatelessAuthTests
    {
        public const string ListeningOn = "http://localhost:2337/";

        protected readonly ServiceStackHost appHost;
        protected string ApiKey;
        protected string ApiKeyTest;
        protected string ApiKeyWithRole;
        protected IManageApiKeys apiRepo;
        protected ApiKeyAuthProvider apiProvider;
        protected string userId;
        protected string userIdWithRoles;

        protected virtual ServiceStackHost CreateAppHost()
        {
            return new AppHost();
        }

        public StatelessAuthTests()
        {
            //LogManager.LogFactory = new ConsoleLogFactory();
            appHost = CreateAppHost()
               .Init()
               .Start("http://*:2337/");

            var client = GetClient();
            var response = client.Post(new Register
            {
                UserName = "user",
                Password = "p@55word",
                Email = "as@if{0}.com",
                DisplayName = "DisplayName",
                FirstName = "FirstName",
                LastName = "LastName",
            });

            userId = response.UserId;
            apiRepo = (IManageApiKeys)appHost.Resolve<IAuthRepository>();
            var user1Client = GetClientWithUserPassword(alwaysSend:true);
            ApiKey = user1Client.Get(new GetApiKeys { Environment = "live" }).Results[0].Key;

            apiProvider = (ApiKeyAuthProvider)AuthenticateService.GetAuthProvider(ApiKeyAuthProvider.Name);

            response = client.Post(new Register
            {
                UserName = "user2",
                Password = "p@55word",
                Email = "as2@if{0}.com",
                DisplayName = "DisplayName2",
                FirstName = "FirstName2",
                LastName = "LastName2",
            });
            userIdWithRoles = response.UserId;
            var user2Client = GetClientWithUserPassword(alwaysSend: true, userName: "user2");
            ApiKeyWithRole = user2Client.Get(new GetApiKeys { Environment = "live" }).Results[0].Key;

            ListeningOn.CombineWith("/assignroles").AddQueryParam("authsecret", "secret")
                .PostJsonToUrl(new AssignRoles
                {
                    UserName = "user2",
                    Roles = new List<string> { "TheRole" },
                    Permissions = new List<string> { "ThePermission" }
                }.ToJson());
        }

        [OneTimeTearDown]
        public void TestFixtureTearDown()
        {
            appHost.Dispose();
        }

        [Ignore("Debug Run")]
        [Test]
        public void RunFor10Mins()
        {
            Process.Start(ListeningOn);
            Thread.Sleep(TimeSpan.FromMinutes(10));
        }

        public const string Username = "user";
        public const string Password = "p@55word";

        protected virtual IServiceClient GetClientWithUserPassword(bool alwaysSend = false, string userName = null)
        {
            return new JsonServiceClient(ListeningOn)
            {
                UserName = userName ?? Username,
                Password = Password,
                AlwaysSendBasicAuthHeader = alwaysSend,
            };
        }

        protected virtual IServiceClient GetClientWithApiKey(string apiKey = null)
        {
            return new JsonServiceClient(ListeningOn)
            {
                Credentials = new NetworkCredential(apiKey ?? ApiKey, ""),
            };
        }

        protected virtual IServiceClient GetClientWithBearerToken(string bearerToken)
        {
            return new JsonServiceClient(ListeningOn)
            {
                BearerToken = bearerToken,
            };
        }

        protected virtual IServiceClient GetClient() => new JsonServiceClient(ListeningOn);

        [Test]
        public void Does_create_multiple_ApiKeys()
        {
            var apiKeys = apiRepo.GetUserApiKeys(userId);
            Assert.That(apiKeys.Count, Is.EqualTo(
                apiProvider.Environments.Length * apiProvider.KeyTypes.Length));

            Assert.That(apiKeys.All(x => x.UserAuthId != null));
            Assert.That(apiKeys.All(x => x.Environment != null));
            Assert.That(apiKeys.All(x => x.KeyType != null));
            Assert.That(apiKeys.All(x => x.CreatedDate != default(DateTime)));
            Assert.That(apiKeys.All(x => x.CancelledDate == null));
            Assert.That(apiKeys.All(x => x.ExpiryDate == null));

            foreach (var apiKey in apiKeys)
            {
                var byId = apiRepo.GetApiKey(ApiKey);
                Assert.That(byId.Id, Is.EqualTo(ApiKey));
            }
        }

        [Test]
        public void Does_return_multiple_ApiKeys()
        {
            var apiKeys = GetClientWithUserPassword(alwaysSend: true).Get(new GetApiKeys { Environment = "test" }).Results;
            Assert.That(apiKeys.Count, Is.EqualTo(apiProvider.KeyTypes.Length));
            apiKeys = GetClientWithUserPassword(alwaysSend: true).Get(new GetApiKeys { Environment = "live" }).Results;
            Assert.That(apiKeys.Count, Is.EqualTo(apiProvider.KeyTypes.Length));
        }

        [Test]
        public void Regenerating_AuthKeys_invalidates_existing_Keys_and_enables_new_keys()
        {
            var client = new JsonServiceClient(ListeningOn)
            {
                Credentials = new NetworkCredential(ApiKey, ""),
            };

            var apiKeyResponse = client.Get(new GetApiKeys { Environment = "live" });

            var oldApiKey = apiKeyResponse.Results[0].Key;
            client = new JsonServiceClient(ListeningOn)
            {
                BearerToken = oldApiKey,
            };

            //Key IsValid
            var request = new Secured { Name = "regenerate" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var regenResponse = client.Send(new RegenerateApiKeys { Environment = "live" });

            try
            {
                //Key is no longer valid
                apiKeyResponse = client.Get(new GetApiKeys { Environment = "live" });
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Forbidden));
            }

            //Change to new Valid Key
            client.BearerToken = regenResponse.Results[0].Key;
            apiKeyResponse = client.Get(new GetApiKeys { Environment = "live" });

            Assert.That(regenResponse.Results.Map(x => x.Key), Is.EquivalentTo(
                apiKeyResponse.Results.Map(x => x.Key)));
        }

        [Test]
        public void Doesnt_allow_using_expired_keys()
        {
            var client = new JsonServiceClient(ListeningOn)
            {
                Credentials = new NetworkCredential(ApiKey, ""),
            };

            var authResponse = client.Get(new Authenticate());

            var apiKeys = apiRepo.GetUserApiKeys(authResponse.UserId)
                .Where(x => x.Environment == "test")
                .ToList();

            var oldApiKey = apiKeys[0].Id;
            client = new JsonServiceClient(ListeningOn)
            {
                BearerToken = oldApiKey,
            };

            //Key IsValid
            var request = new Secured { Name = "live" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            apiKeys[0].ExpiryDate = DateTime.UtcNow.AddMinutes(-1);
            apiRepo.StoreAll(new[] { apiKeys[0] });

            try
            {
                //Key is no longer valid
                client.Get(new GetApiKeys { Environment = "test" });
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Forbidden));
            }

            client = new JsonServiceClient(ListeningOn)
            {
                Credentials = new NetworkCredential(ApiKey, ""),
            };
            var regenResponse = client.Send(new RegenerateApiKeys { Environment = "test" });

            //Change to new Valid Key
            client.BearerToken = regenResponse.Results[0].Key;
            var apiKeyResponse = client.Get(new GetApiKeys { Environment = "test" });

            Assert.That(regenResponse.Results.Map(x => x.Key), Is.EquivalentTo(
                apiKeyResponse.Results.Map(x => x.Key)));
        }

        [Test]
        public void Doesnt_allow_sending_invalid_APIKeys()
        {
            var client = new JsonServiceClient(ListeningOn)
            {
                Credentials = new NetworkCredential("InvalidKey", ""),
            };

            var request = new Secured { Name = "live" };
            try
            {
                var response = client.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.ResponseStatus.ErrorCode, Is.EqualTo("NotFound"));
                Assert.That(ex.ResponseStatus.Message, Is.EqualTo("ApiKey does not exist"));
                Assert.That(ex.ResponseStatus.StackTrace, Is.Not.Null);
            }
        }

        [Test]
        public void Authenticating_once_with_BasicAuth_does_not_establish_auth_session()
        {
            var client = GetClientWithUserPassword(alwaysSend: true);

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
            response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = newClient.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public void Authenticating_once_with_JWT_does_not_establish_auth_session()
        {
            var client = GetClientWithUserPassword(alwaysSend: true);

            var authResponse = client.Send(new Authenticate());
            Assert.That(authResponse.BearerToken, Is.Not.Null);

            var jwtClient = GetClientWithBearerToken(authResponse.BearerToken);
            var request = new Secured { Name = "test" };
            var response = jwtClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
            response = jwtClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(jwtClient.GetSessionId());

            try
            {
                response = newClient.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public void Authenticating_with_JWT_cookie_does_allow_multiple_authenticated_requests()
        {
            var client = GetClientWithUserPassword(alwaysSend: true);

            var authResponse = client.Send(new Authenticate());
            Assert.That(authResponse.BearerToken, Is.Not.Null);

            var jwtClient = GetClient();
            jwtClient.SetTokenCookie(authResponse.BearerToken);

            var request = new Secured { Name = "test" };
            var response = jwtClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            var cookieValue = jwtClient.GetTokenCookie();
            newClient.SetTokenCookie(cookieValue);
            response = newClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void Authenticating_once_with_ApiKeyAuth_does_not_establish_auth_session()
        {
            var client = GetClientWithApiKey();

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = newClient.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public async Task Authenticating_once_with_ApiKeyAuth_does_not_establish_auth_session_Async()
        {
            var client = GetClientWithApiKey();

            var request = new Secured { Name = "test" };
            var response = await client.SendAsync<SecuredResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = await newClient.SendAsync<SecuredResponse>(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public void Authenticating_once_with_ApiKeyAuth_BearerToken_does_not_establish_auth_session()
        {
            var client = GetClientWithBearerToken(ApiKey);

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = newClient.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public async Task Authenticating_once_with_ApiKeyAuth_BearerToken_does_not_establish_auth_session_Async()
        {
            var client = GetClientWithBearerToken(ApiKey);

            var request = new Secured { Name = "test" };
            var response = await client.SendAsync<SecuredResponse>(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = await newClient.SendAsync<SecuredResponse>(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        [Test]
        public void Authenticating_once_with_CredentialsAuth_does_establish_auth_session()
        {
            var client = GetClient();

            try
            {
                client.Send(new Authenticate());
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }

            client.Post(new Authenticate
            {
                provider = "credentials",
                UserName = Username,
                Password = Password,
            });

            client.Send(new Authenticate());

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            response = newClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void Can_Authenticate_with_ApiKeyAuth_SessionCacheDuration()
        {
            apiProvider.SessionCacheDuration = TimeSpan.FromSeconds(60);

            var client = GetClientWithBearerToken(ApiKey);

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            //Does not preserve UserSession
            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());
            try
            {
                response = newClient.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException webEx)
            {
                Assert.That(webEx.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }

            var cachedSession = appHost.GetCacheClient(null).Get<IAuthSession>(ApiKeyAuthProvider.GetSessionKey(ApiKey));
            Assert.That(cachedSession.IsAuthenticated);

            //Can call multiple times using cached UserSession
            response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            apiProvider.SessionCacheDuration = null;
        }

        public static void AssertNoAccessToSecuredByRoleAndPermission(IServiceClient client)
        {
            try
            {
                client.Send(new SecuredByRole { Name = "test" });
                Assert.Fail("Should Throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Forbidden));
            }

            try
            {
                client.Send(new SecuredByPermission { Name = "test" });
                Assert.Fail("Should Throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Forbidden));
            }
        }

        [Test]
        public void Can_not_access_SecuredBy_Role_or_Permission_without_TheRole_or_ThePermission()
        {
            var client = GetClientWithUserPassword(alwaysSend: true);
            AssertNoAccessToSecuredByRoleAndPermission(client);

            client = GetClientWithApiKey();
            AssertNoAccessToSecuredByRoleAndPermission(client);

            var bearerToken = client.Get(new Authenticate()).BearerToken;
            client = GetClientWithBearerToken(bearerToken);
            AssertNoAccessToSecuredByRoleAndPermission(client);

            client = GetClient();
            client.Post(new Authenticate
            {
                provider = "credentials",
                UserName = Username,
                Password = Password,
            });
            AssertNoAccessToSecuredByRoleAndPermission(client);
        }

        public static void AssertAccessToSecuredByRoleAndPermission(IServiceClient client)
        {
            var roleResponse = client.Send(new SecuredByRole { Name = "test" });
            Assert.That(roleResponse.Result, Is.EqualTo("test"));

            var permResponse = client.Send(new SecuredByPermission { Name = "test" });
            Assert.That(permResponse.Result, Is.EqualTo("test"));
        }

        [Test]
        public void Can_access_SecuredBy_Role_or_Permission_with_TheRole_and_ThePermission()
        {
            var client = GetClientWithUserPassword(alwaysSend: true, userName: "user2");
            AssertAccessToSecuredByRoleAndPermission(client);

            client = GetClientWithApiKey(ApiKeyWithRole);
            AssertAccessToSecuredByRoleAndPermission(client);

            var bearerToken = client.Get(new Authenticate()).BearerToken;
            client = GetClientWithBearerToken(bearerToken);
            AssertAccessToSecuredByRoleAndPermission(client);

            client = GetClient();
            client.Post(new Authenticate
            {
                provider = "credentials",
                UserName = "user2",
                Password = Password,
            });
            AssertAccessToSecuredByRoleAndPermission(client);
        }

        [Test]
        public void Can_not_access_Secure_service_with_invalidated_token()
        {
            var jwtProvider = (JwtAuthProvider)AuthenticateService.GetAuthProvider(JwtAuthProvider.Name);

            var token = jwtProvider.CreateJwtBearerToken(new AuthUserSession
            {
                UserAuthId = "1",
                DisplayName = "Test",
                Email = "as@if.com"
            });

            var client = GetClientWithBearerToken(token);

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            jwtProvider.InvalidateTokensIssuedBefore = DateTime.UtcNow.AddSeconds(1);

            try
            {
                response = client.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
                Assert.That(ex.ErrorCode, Is.EqualTo(typeof(TokenException).Name));
            }
            finally
            {
                jwtProvider.InvalidateTokensIssuedBefore = null;
            }
        }

        [Test]
        public void Can_not_access_Secure_service_with_expired_token()
        {
            var jwtProvider = (JwtAuthProvider)AuthenticateService.GetAuthProvider(JwtAuthProvider.Name);
            jwtProvider.CreatePayloadFilter = (jwtPayload,session) =>
                jwtPayload["exp"] = DateTime.UtcNow.AddSeconds(-1).ToUnixTime().ToString();

            var token = jwtProvider.CreateJwtBearerToken(new AuthUserSession
            {
                UserAuthId = "1",
                DisplayName = "Test",
                Email = "as@if.com"
            });

            jwtProvider.CreatePayloadFilter = null;

            var client = GetClientWithBearerToken(token);

            try
            {
                var request = new Secured { Name = "test" };
                var response = client.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
                Assert.That(ex.ErrorCode, Is.EqualTo(typeof(TokenException).Name));
            }
        }

        [Test]
        public void Can_Auto_reconnect_with_BasicAuth_after_expired_token()
        {
            var authClient = GetClientWithUserPassword(alwaysSend: true);

            var called = 0;
            var client = new JsonServiceClient(ListeningOn)
            {
                BearerToken = CreateExpiredToken(),
            };
            client.OnAuthenticationRequired = () =>
            {
                called++;
                client.BearerToken = authClient.Send(new Authenticate()).BearerToken;
            };

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            Assert.That(called, Is.EqualTo(1));
        }

        [Test]
        public async Task Can_Auto_reconnect_with_BasicAuth_after_expired_token_Async()
        {
            var authClient = GetClientWithUserPassword(alwaysSend: true);

            var called = 0;
            var client = new JsonServiceClient(ListeningOn) {
                BearerToken = CreateExpiredToken(),
            };
            client.OnAuthenticationRequired = () =>
            {
                called++;
                client.BearerToken = authClient.Send(new Authenticate()).BearerToken;
            };

            var request = new Secured { Name = "test" };
            var response = await client.SendAsync(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            response = await client.SendAsync(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            Assert.That(called, Is.EqualTo(1));
        }

        [Test]
        public void Can_not_access_Secure_service_on_unsecured_connection_when_RequireSecureConnection()
        {
            var jwtProvider = (JwtAuthProvider)AuthenticateService.GetAuthProvider(JwtAuthProvider.Name);
            jwtProvider.RequireSecureConnection = true;

            var token = jwtProvider.CreateJwtBearerToken(new AuthUserSession
            {
                UserAuthId = "1",
                DisplayName = "Test",
                Email = "as@if.com"
            });

            var client = GetClientWithBearerToken(token);

            try
            {
                var request = new Secured { Name = "test" };
                var response = client.Send(request);
                Assert.Fail("Should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Forbidden));
                Assert.That(ex.ErrorCode, Is.EqualTo("Forbidden"));
            }
            finally
            {
                jwtProvider.RequireSecureConnection = false;
            }
        }

        [Test]
        public void Can_ConvertSessionToToken()
        {
            var client = GetClient();

            client.Send(new Authenticate
            {
                provider = "credentials",
                UserName = Username,
                Password = Password,
            });

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var newClient = GetClient();
            newClient.SetSessionId(client.GetSessionId());

            var tokenResponse = newClient.Send(new ConvertSessionToToken());
            var tokenCookie = newClient.GetTokenCookie();
            response = newClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            try
            {
                response = client.Send(request);
                Assert.Fail("should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }

            response = newClient.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));
        }

        [Test]
        public void Can_ConvertSessionToToken_when_authenticating()
        {
            var client = GetClient();

            var authResponse = client.Send(new Authenticate
            {
                provider = "credentials",
                UserName = Username,
                Password = Password,
                UseTokenCookie = true
            });

            var token = client.GetTokenCookie();
            Assert.That(token, Is.Not.Null);
            Assert.That(token, Is.EqualTo(authResponse.BearerToken));

            var request = new Secured { Name = "test" };
            var response = client.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var clientWithToken = GetClient();
            clientWithToken.SetTokenCookie(client.GetTokenCookie());

            response = clientWithToken.Send(request);
            Assert.That(response.Result, Is.EqualTo(request.Name));

            var clientWithSession = GetClient();
            clientWithSession.SetSessionId(client.GetSessionId());

            try
            {
                response = clientWithSession.Send(request);
                Assert.Fail("should throw");
            }
            catch (WebServiceException ex)
            {
                Assert.That(ex.StatusCode, Is.EqualTo((int)HttpStatusCode.Unauthorized));
            }
        }

        private static string CreateExpiredToken()
        {
            var jwtProvider = (JwtAuthProvider)AuthenticateService.GetAuthProvider(JwtAuthProvider.Name);
            jwtProvider.CreatePayloadFilter = (jwtPayload, session) =>
                jwtPayload["exp"] = DateTime.UtcNow.AddSeconds(-1).ToUnixTime().ToString();

            var token = jwtProvider.CreateJwtBearerToken(new AuthUserSession
            {
                UserAuthId = "1",
                DisplayName = "Test",
                Email = "as@if.com"
            });

            jwtProvider.CreatePayloadFilter = null;
            return token;
        }
    }
}