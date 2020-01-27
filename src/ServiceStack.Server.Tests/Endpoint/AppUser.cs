using System;
using ServiceStack.Auth;
using ServiceStack.DataAnnotations;

namespace ServiceStack.Server.Tests.Endpoint
{
    [Index(Name = nameof(Key))]
    public class AppUser : UserAuth
    {
        public string Key { get; set; }
        public string ProfileUrl { get; set; }
        public string LastLoginIp { get; set; }
        public DateTime? LastLoginDate { get; set; }
    }
}