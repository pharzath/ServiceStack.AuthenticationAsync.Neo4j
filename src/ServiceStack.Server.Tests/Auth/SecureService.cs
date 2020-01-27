namespace ServiceStack.Server.Tests.Auth
{
    [Authenticate]
    public class SecureService : Service
    {
        public object Any(Secured request)
        {
            return new SecuredResponse { Result = request.Name };
        }

        public object Any(GetAuthUserSession request)
        {
            return Request.GetSession() as AuthUserSession;
        }

        [RequiredRole("TheRole")]
        public object Any(SecuredByRole request)
        {
            return new SecuredResponse { Result = request.Name };
        }

        [RequiredPermission("ThePermission")]
        public object Any(SecuredByPermission request)
        {
            return new SecuredResponse { Result = request.Name };
        }
    }
}