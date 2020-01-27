using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using Funq;
using ServiceStack.Auth;
using ServiceStack.DataAnnotations;
using ServiceStack.Web;

//The entire C# code for the stand-alone RazorRockstars demo.
namespace ServiceStack.Server.Tests.Auth
{
    public class AppHost : AppSelfHostBase
    {
        public AppHost() : base("Test Auth", typeof(AppHost).Assembly) { }

        public RSAParameters? JwtRsaPrivateKey;
        public RSAParameters? JwtRsaPublicKey;
        public bool JwtEncryptPayload = false;
        public List<byte[]> FallbackAuthKeys = new List<byte[]>();
        public List<RSAParameters> FallbackPublicKeys = new List<RSAParameters>();
        public Func<IRequest, IAuthRepository> GetAuthRepositoryFn;

        public Action<Container> Use;

        public override void Configure(Container container)
        {
            Use?.Invoke(container);

            SetConfig(new HostConfig
            {
                AdminAuthSecret = "secret",
                DebugMode = true,
            });

            Plugins.Add(new AuthFeature(() => new AuthUserSession(),
                new IAuthProvider[] {
                    new BasicAuthProvider(AppSettings),
                    new CredentialsAuthProvider(AppSettings),
                    new ApiKeyAuthProvider(AppSettings) { RequireSecureConnection = false },
                    new JwtAuthProvider(AppSettings)
                    {
                        AuthKey = JwtRsaPrivateKey != null || JwtRsaPublicKey != null ? null : AesUtils.CreateKey(),
                        RequireSecureConnection = false,
                        HashAlgorithm = JwtRsaPrivateKey != null || JwtRsaPublicKey != null ? "RS256" : "HS256",
                        PublicKey = JwtRsaPublicKey,
                        PrivateKey = JwtRsaPrivateKey,
                        EncryptPayload = JwtEncryptPayload,
                        FallbackAuthKeys = FallbackAuthKeys,
                        FallbackPublicKeys = FallbackPublicKeys,
                    },
                })
            {
                IncludeRegistrationService = true,
            });

            container.Resolve<IAuthRepository>().InitSchema();
        }

        public override IAuthRepository GetAuthRepository(IRequest req = null)
        {
            return GetAuthRepositoryFn != null
                ? GetAuthRepositoryFn(req)
                : base.GetAuthRepository(req);
        }
    }

    public class Rockstar
    {
        public static Rockstar[] SeedData = new[] {
            new Rockstar(1, "Jimi", "Hendrix", 27),
            new Rockstar(2, "Janis", "Joplin", 27),
            new Rockstar(3, "Jim", "Morrisson", 27),
            new Rockstar(4, "Kurt", "Cobain", 27),
            new Rockstar(5, "Elvis", "Presley", 42),
            new Rockstar(6, "Michael", "Jackson", 50),
        };

        [AutoIncrement]
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int? Age { get; set; }
        public bool Alive { get; set; }

        public Rockstar() { }
        public Rockstar(int id, string firstName, string lastName, int age)
        {
            Id = id;
            FirstName = firstName;
            LastName = lastName;
            Age = age;
        }
    }

    [Route("/rockstars")]
    [Route("/rockstars/aged/{Age}")]
    [Route("/rockstars/delete/{Delete}")]
    [Route("/rockstars/{Id}")]
    public class Rockstars : IReturn<RockstarsResponse>
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int? Age { get; set; }
        public bool Alive { get; set; }
        public string Delete { get; set; }
        public string View { get; set; }
        public string Template { get; set; }
    }

    [DataContract] //Attrs for CSV Format to recognize it's a DTO and serialize the Enumerable property
    public class RockstarsResponse
    {
        [DataMember]
        public int Total { get; set; }
        [DataMember]
        public int? Aged { get; set; }
        [DataMember]
        public List<Rockstar> Results { get; set; }
    }

    [Route("/ilist1/{View}")]
    public class IList1
    {
        public string View { get; set; }
    }

    [Route("/ilist2/{View}")]
    public class IList2
    {
        public string View { get; set; }
    }

    [Route("/ilist3/{View}")]
    public class IList3
    {
        public string View { get; set; }
    }

    [Route("/partialmodel")]
    public class PartialModel
    {
        public IEnumerable<PartialChildModel> Items { get; set; }
    }
    public class PartialChildModel
    {
        public string SomeProperty { get; set; }
    }

    public class GetAllRockstars : IReturn<RockstarsResponse> { }

    public class RedirectWithoutQueryStringFilterAttribute : RequestFilterAttribute
    {
        public override void Execute(IRequest req, IResponse res, object requestDto)
        {
            if (req.QueryString.Count > 0)
            {
                res.RedirectToUrl(req.PathInfo);
            }
        }
    }

    [RedirectWithoutQueryStringFilter]
    public class RedirectWithoutQueryString
    {
        public int Id { get; set; }
    }

    [Route("/Content/hello/{Name*}")]
    public class TestWildcardRazorPage
    {
        public string Name { get; set; }
    }

    public class IssueServices : Service
    {
        public object Get(TestWildcardRazorPage request)
        {
            return request;
        }
    }

    [Route("/test/session")]
    public class TestSession : IReturn<TestSessionResponse> { }

    [Route("/test/session/view")]
    public class TestSessionView : IReturn<TestSessionResponse> { }

    public class TestSessionResponse
    {
        public string UserAuthId { get; set; }
        public bool IsAuthenticated { get; set; }
    }

    public class TestSessionAttribute : RequestFilterAttribute
    {
        public override void Execute(IRequest req, IResponse res, object requestDto)
        {
            var session = req.GetSession();
            if (!session.IsAuthenticated)
            {
                res.StatusCode = (int)HttpStatusCode.Unauthorized;
                res.EndRequestWithNoContent();
            }
        }
    }

    public class TestSessionService : Service
    {
        [TestSession]
        public object Any(TestSession request)
        {
            var session = base.Request.GetSession();
            return new TestSessionResponse
            {
                UserAuthId = session.UserAuthId,
                IsAuthenticated = session.IsAuthenticated,
            };
        }

        public object Any(TestSessionView request)
        {
            return new TestSessionResponse();
        }
    }
}
