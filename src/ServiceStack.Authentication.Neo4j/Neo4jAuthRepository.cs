using Neo4j.Driver;
using ServiceStack;
using ServiceStack.Auth;

namespace Neo4jAuthRepository;

    // ReSharper disable once InconsistentNaming
    public class Neo4jAuthRepositoryAsync : Neo4jAuthRepositoryAsync<UserAuth, UserAuthDetails>
    {
        public Neo4jAuthRepositoryAsync(IDriver driver) 
            : base(driver) { }
    }
    
    // ReSharper disable once InconsistentNaming
    public class Neo4jAuthRepositoryAsync<TUserAuth, TUserAuthDetails> : 
        IUserAuthRepositoryAsync, 
        IClearableAsync, 
        IRequiresSchemaAsync, 
        IManageApiKeysAsync
        where TUserAuth : class, IUserAuth, new()
        where TUserAuthDetails : class, IUserAuthDetails, new()
    {
        private static class Label
        {
            public const string AuthIdSeq = "AuthIdSeq";    
            public const string UserAuth = "UserAuth";
            public const string UserAuthDetails = "UserAuthDetails";
            public const string ApiKey = "ApiKey";
        }

        private static class Rel
        {
            public const string HasUserAuthDetails = "HAS_USER_AUTH_DETAILS";
            public const string HasApiKey = "HAS_API_KEY";
        }

        private static class Query
        {
            public static string IdScopeConstraint => $@"
                CREATE CONSTRAINT ON (seq:{Label.AuthIdSeq}) ASSERT seq.Scope IS UNIQUE";

            public static string UserAuthConstraint => $@"
                CREATE CONSTRAINT ON (userAuth:{Label.UserAuth}) ASSERT userAuth.Id IS UNIQUE";

            public static string UserAuthDetailsConstraint => $@"
                CREATE CONSTRAINT ON (details:{Label.UserAuthDetails}) ASSERT details.Id IS UNIQUE";

            public static string ApiKeyConstraint => $@"
                CREATE CONSTRAINT ON (apiKey:{Label.ApiKey}) ASSERT apiKey.Id IS UNIQUE";

            public static string NextSequence => $@"
                MERGE (seq:{Label.AuthIdSeq} {{Scope: $scope}})
                SET seq.Value = COALESCE(seq.Value, 0) + 1
                RETURN seq.Value";

            public static string DeleteAllSequence => $@"
                MATCH (seq:{Label.AuthIdSeq})
                DELETE seq";

            public static string CreateOrUpdateUserAuth => $@"
                MERGE (user:{Label.UserAuth} {{Id: $user.Id}})
                SET user = $user";

            public static string UserAuthById => $@"
                MATCH (user:{Label.UserAuth} {{Id: $id}})
                RETURN user";

            public static string UserAuthByName => $@"
                MATCH (user:{Label.UserAuth} {{UserName: $name}})
                RETURN user";

            public static string UserAuthByEmail => $@"
                MATCH (user:{Label.UserAuth} {{Email: $name}})
                RETURN user";

            public static string UserAuthDetailsById => $@"
                MATCH (:{Label.UserAuth} {{Id: $id}})-[:{Rel.HasUserAuthDetails}]->(details:{Label.UserAuthDetails})
                RETURN details";

            public static string DeleteUserAuth => $@"
                MATCH (user:{Label.UserAuth} {{Id: $id}})
                OPTIONAL MATCH (user)-[rDetails:{Rel.HasUserAuthDetails}]->(details:{Label.UserAuthDetails})
                OPTIONAL MATCH (user)-[rApiKey:{Rel.HasApiKey}]->(apiKey:{Label.ApiKey})
                DELETE user, details, apiKey, rDetails, rApiKey";

            public static string DeleteAllUserAuth => $@"
                MATCH (user:{Label.UserAuth})
                OPTIONAL MATCH (user)-[rDetails:{Rel.HasUserAuthDetails}]->(details:{Label.UserAuthDetails})
                OPTIONAL MATCH (user)-[rApiKey:{Rel.HasApiKey}]->(apiKey:{Label.ApiKey})
                DELETE user, details, apiKey, rDetails, rApiKey";

            public static string UserAuthDetailsByProviderAndUserId => $@"
                MATCH (details:{Label.UserAuthDetails})
                WHERE details.Provider = $provider AND details.UserId = $userId
                RETURN details";

            public static string UserAuthByProviderAndUserId => $@"
                MATCH (details:{Label.UserAuthDetails})
                WHERE details.Provider = $provider AND details.UserId = $userId
                MATCH (userAuth:{Label.UserAuth})-[:{Rel.HasUserAuthDetails}]->(details:{Label.UserAuthDetails})
                RETURN DISTINCT userAuth";

            public static string CreateOrUpdateUserAuthDetails => $@"
                MERGE (details:{Label.UserAuthDetails} {{Id: $details.Id}})
                SET details = $details
                WITH details
                MATCH (user:{Label.UserAuth} {{Id: $id}})
                MERGE (user)-[:{Rel.HasUserAuthDetails}]->(details)";

            public static string ApiKeyById => $@"
                MATCH (apiKey:{Label.ApiKey} {{Id: $id}})
                RETURN apiKey";

            public static string ActiveApiKeysByUserAuthId => $@"
                MATCH (userAuth:{Label.UserAuth} {{Id: $id}})-[:{Rel.HasApiKey}]->(apiKey:{Label.ApiKey})
                WHERE apiKey.CancelledDate Is null AND (apiKey.ExpiryDate IS null OR apiKey.ExpiryDate >= $expiry)
                RETURN apiKey";

            public static string UpdateApiKeys => $@"
                UNWIND $keys AS key
                MERGE (apiKey:{Label.ApiKey} {{Id: key.Id}})
                SET apiKey = key
                WITH apiKey, key
                MATCH (userAuth:{Label.UserAuth} {{Id: toInteger(key.UserAuthId)}})
                MERGE (userAuth)-[:{Rel.HasApiKey}]->(apiKey)";
        }

        private readonly IDriver _driver;
        
        // ReSharper disable once MemberCanBeProtected.Global
        public Neo4jAuthRepositoryAsync(IDriver driver)
        {
            this._driver = driver;

            InitMappers();
        }

        public async Task InitSchemaAsync(CancellationToken token=default)
        {
            await _driver.WriteTxQueryAsync(async tx =>
            {
                await tx.RunAsync(Query.IdScopeConstraint);
                await tx.RunAsync(Query.UserAuthConstraint);
                await tx.RunAsync(Query.UserAuthDetailsConstraint);
            });
        }

        public async Task<IUserAuth> CreateUserAuthAsync(IUserAuth newUser, string password , CancellationToken token=default)
        {
            newUser.ValidateNewUser(password);

            await AssertNoExistingUserAsync(newUser);

            newUser.PopulatePasswordHashes(password);
            newUser.CreatedDate = DateTime.UtcNow;
            newUser.ModifiedDate = newUser.CreatedDate;

            await SaveUserAsync(newUser);
            return newUser;
        }

        private Task SaveUserAsync(IUserAuth userAuth)
        {
            return _driver.WriteTxQueryAsync(async tx =>
            {
                if (userAuth.Id == default)
                    userAuth.Id = await NextSequenceAsync(tx, Label.UserAuth);

                var parameters = new
                {
                    user = userAuth.ConvertTo<Dictionary<string, object>>()
                };

                await tx.RunAsync(Query.CreateOrUpdateUserAuth, parameters);
            });
        }

        private async Task<int> NextSequenceAsync(IAsyncTransaction tx, string scope)
        {
            var parameters = new { scope };

            var result = await tx.RunAsync(Query.NextSequence, parameters);

            var record = await result.SingleAsync();
            return record[0].As<int>();
        }

        private async Task AssertNoExistingUserAsync(IUserAuth newUser, IUserAuth? exceptForExistingUser = null)
        {
            IUserAuth? existingUser;
            if (newUser.UserName != null)
            {
                existingUser = await GetUserAuthByUserNameAsync(newUser.UserName);
                if (existingUser != null
                    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                    throw new ArgumentException(string.Format(ErrorMessages.UserAlreadyExistsFmt, newUser.UserName.SafeInput()));
            }

            if (newUser.Email == null) return;
            
            existingUser = await GetUserAuthByUserNameAsync(newUser.Email);
            if (existingUser != null
                && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                throw new ArgumentException(string.Format(ErrorMessages.EmailAlreadyExistsFmt, newUser.Email.SafeInput()));
        }

        public async Task<IUserAuth> UpdateUserAuthAsync(IUserAuth existingUser, IUserAuth newUser, string password,CancellationToken token=default)
        {
            newUser.ValidateNewUser(password);

            await AssertNoExistingUserAsync(newUser, existingUser);

            newUser.Id = existingUser.Id;
            newUser.PopulatePasswordHashes(password, existingUser);
            newUser.CreatedDate = existingUser.CreatedDate;
            newUser.ModifiedDate = DateTime.UtcNow;
            await SaveUserAsync(newUser);

            return newUser;
        }

        public async Task<IUserAuth> UpdateUserAuthAsync(IUserAuth existingUser, IUserAuth newUser,CancellationToken token=default)
        {
            newUser.ValidateNewUser();

            await AssertNoExistingUserAsync(newUser);

            newUser.Id = existingUser.Id;
            newUser.PasswordHash = existingUser.PasswordHash;
            newUser.Salt = existingUser.Salt;
            newUser.DigestHa1Hash = existingUser.DigestHa1Hash;
            newUser.CreatedDate = existingUser.CreatedDate;
            newUser.ModifiedDate = DateTime.UtcNow;
            await SaveUserAsync(newUser);

            return newUser;
        }

        public async Task<IUserAuth?> GetUserAuthByUserNameAsync(string userNameOrEmail,CancellationToken token=default)
        {
            if (string.IsNullOrEmpty( userNameOrEmail))
                return null;

            var isEmail = userNameOrEmail.Contains("@");

            var parameters = new
            {
                name = userNameOrEmail
            };

            return await _driver.ReadTxQueryAsync(async tx =>
            {
                var result = await tx.RunAsync(isEmail ? Query.UserAuthByEmail : Query.UserAuthByName, parameters);
                return (await result.Map<IUserAuth>()).SingleOrDefault();
            });
        }

        public async Task<IUserAuth?> TryAuthenticateAsync(string userName, string password,CancellationToken token=default)
        {
            var userAuth = await GetUserAuthByUserNameAsync(userName, token);
            if (userAuth is null)
                return null;

            if (userAuth.VerifyPassword(password, out var needsRehash))
            {
                await this.RecordSuccessfulLoginAsync(userAuth, needsRehash, password, token: token);

                return userAuth;
            }

            await this.RecordInvalidLoginAttemptAsync(userAuth, token: token);
            
            return null;
        }

        public async Task<IUserAuth?> TryAuthenticateAsync(Dictionary<string, string> digestHeaders, string privateKey, int nonceTimeOut, string sequence,CancellationToken token=default )
        {
            var userAuth = await GetUserAuthByUserNameAsync(digestHeaders["username"], token);
            if (userAuth == null)
                return null;

            if (userAuth.VerifyDigestAuth(digestHeaders, privateKey, nonceTimeOut, sequence))
            {
                await this.RecordSuccessfulLoginAsync(userAuth, token: token);

                return userAuth;
            }

            await this.RecordInvalidLoginAttemptAsync(userAuth, token: token);
            
            return null;
        }

        public async Task LoadUserAuthAsync(IAuthSession session, IAuthTokens tokens,CancellationToken token=default)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            var userAuth = await GetUserAuthAsync(session, tokens, token);
            await LoadUserAuthAsync(session, userAuth!,token);
        }

        private async Task LoadUserAuthAsync(IAuthSession session, IUserAuth userAuth,CancellationToken token=default)
        {
            await session.PopulateSessionAsync(userAuth, this, token: token);
        }

        public async Task<IUserAuth?> GetUserAuthAsync(string userAuthId,CancellationToken token=default)
        {
            TryConvertToInteger(userAuthId, "userAuthId", out var idVal);

            var parameters = new
            {
                id = idVal
            };

            return await _driver.ReadTxQueryAsync(async tx =>
            {
                var result = await tx.RunAsync(Query.UserAuthById, parameters);
                return (await result.Map<TUserAuth>()).SingleOrDefault();
            });
        }

        public async Task SaveUserAuthAsync(IAuthSession authSession,CancellationToken token=default)
        {
            var userAuth = !authSession.UserAuthId.IsNullOrEmpty()
                ? (TUserAuth)(await GetUserAuthAsync(authSession.UserAuthId, token))!
                : authSession.ConvertTo<TUserAuth>();

            if (userAuth.Id == default && !authSession.UserAuthId.IsNullOrEmpty())
            {
                TryConvertToInteger(authSession.UserAuthId, "authSession.UserAuthId", out var idVal);

                userAuth.Id = idVal;
            }

            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default)
                userAuth.CreatedDate = userAuth.ModifiedDate;

            await SaveUserAsync(userAuth);

            if (authSession.UserAuthId.IsNullOrEmpty())
            {
                authSession.UserAuthId = userAuth.Id.ToString();
            }
        }

        public async Task SaveUserAuthAsync(IUserAuth userAuth,CancellationToken token=default)
        {
            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default)
                userAuth.CreatedDate = userAuth.ModifiedDate;

            await SaveUserAsync(userAuth);
        }

        public async Task DeleteUserAuthAsync(string userAuthId,CancellationToken token=default)
        {
            TryConvertToInteger(userAuthId, "userAuthId", out var idVal);

            var parameters = new
            {
                id = idVal
            };

            await _driver.WriteQueryAsync(Query.DeleteUserAuth, parameters);
        }

        public async Task<List<IUserAuthDetails>> GetUserAuthDetailsAsync(string userAuthId,CancellationToken token=default)
        {
            TryConvertToInteger(userAuthId, "userAuthId", out var idVal);

            var parameters = new
            {
                id = idVal
            };

            var items = await _driver.ReadTxQueryAsync(async tx =>
            {
                var results = await tx.RunAsync(Query.UserAuthDetailsById, parameters);
                await results.FetchAsync();
                
                return await results.Map<TUserAuthDetails>();
            });

            return items.Cast<IUserAuthDetails>().ToList();
        }

        public async Task<IUserAuth?> GetUserAuthAsync(IAuthSession authSession, IAuthTokens? tokens,CancellationToken token=default)
        {
            IUserAuth? userAuth;
            if (!authSession.UserAuthId.IsNullOrEmpty())
            {
                userAuth = await GetUserAuthAsync(authSession.UserAuthId, token);
                if (userAuth != null) return userAuth;
            }
            if (!authSession.UserAuthName.IsNullOrEmpty())
            {
                userAuth = await GetUserAuthByUserNameAsync(authSession.UserAuthName, token);
                if (userAuth != null) return userAuth;
            }

            if (tokens == null || tokens.Provider.IsNullOrEmpty() || tokens.UserId.IsNullOrEmpty())
                return null;

            var parameters = new
            {
                userId = tokens.UserId,
                provider = tokens.Provider
            };

            return await _driver.ReadTxQueryAsync(async tx =>
            {
                var result = await tx.RunAsync(Query.UserAuthByProviderAndUserId, parameters);
                return (await result.Map<TUserAuth>()).SingleOrDefault();
            });
        }

        public async Task<IUserAuthDetails> CreateOrMergeAuthSessionAsync(IAuthSession authSession, IAuthTokens tokens,CancellationToken token=default)
        {
            var parameters = new
            {
                userId = tokens.UserId,
                provider = tokens.Provider
            };

            var userAuthDetails = await  _driver.ReadTxQueryAsync(async tx =>
            {
                var result = await tx.RunAsync(Query.UserAuthDetailsByProviderAndUserId, parameters);
                return (await  result.Map<TUserAuthDetails>()).SingleOrDefault() ?? new TUserAuthDetails
                {
                    Provider = tokens.Provider,
                    UserId = tokens.UserId,
                };
            });

            userAuthDetails.PopulateMissing(tokens);
            
            var userAuth = await GetUserAuthAsync(authSession, tokens, token) ?? new TUserAuth();
            userAuth.PopulateMissingExtended(userAuthDetails);

            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default)
                userAuth.CreatedDate = userAuth.ModifiedDate;

            await SaveUserAsync((TUserAuth)userAuth);

            userAuthDetails.UserAuthId = userAuth.Id;
            
            if (userAuthDetails.CreatedDate == default)
                userAuthDetails.CreatedDate = userAuth.ModifiedDate;
            userAuthDetails.ModifiedDate = userAuth.ModifiedDate;

            await _driver.WriteTxQueryAsync(async tx =>
            {
                if (userAuthDetails.Id == default)
                    userAuthDetails.Id = await NextSequenceAsync(tx, Label.UserAuthDetails);

                var detailsParameters = new
                {
                    details = userAuthDetails.ConvertTo<Dictionary<string, object>>(),
                    id = userAuth.Id
                };

                await tx.RunAsync(Query.CreateOrUpdateUserAuthDetails, detailsParameters);
            });

            return userAuthDetails;
        }

        public async Task ClearAsync(CancellationToken token=default)
        {
            await _driver.WriteTxQueryAsync(async tx =>
            {
                await tx.RunAsync(Query.DeleteAllUserAuth);
                await tx.RunAsync(Query.DeleteAllSequence);
            });
        }

        public async void InitApiKeySchema()
        {
            await _driver.WriteQueryAsync(Query.ApiKeyConstraint);
        }

        public async Task<bool> ApiKeyExistsAsync(string apiKey,CancellationToken token=default)
        {
            if (string.IsNullOrEmpty(apiKey))
                return false;

            return (await GetApiKeyAsync(apiKey, token)) != null;
        }

        public async Task<ApiKey?> GetApiKeyAsync(string apiKey,CancellationToken token=default)
        {
            if (string.IsNullOrEmpty(apiKey))
                return null;

            var parameters = new
            {
                id = apiKey
            };

            return await _driver.ReadTxQueryAsync(async tx =>
            {
                var result = await tx.RunAsync(Query.ApiKeyById, parameters);
                return (await result.Map<ApiKey>()).SingleOrDefault();
            });
        }

        public Task<List<ApiKey>> GetUserApiKeysAsync(string userId,CancellationToken token=default)
        {
            TryConvertToInteger(userId, "userId", out var idVal);

            var parameters = new
            {
                id = idVal,
                expiry = DateTime.UtcNow
            };

            return _driver.ReadTxQueryAsync(async tx =>
            {
                var results = await tx.RunAsync(Query.ActiveApiKeysByUserAuthId, parameters);
                return (await results.Map<ApiKey>()).ToList();
            });
        }

        public async Task StoreAllAsync(IEnumerable<ApiKey> apiKeys,CancellationToken token=default)
        {
            var parameters = new
            {
                keys = apiKeys.Select(p => p.ToObjectDictionary())
            };

            await _driver.WriteQueryAsync(Query.UpdateApiKeys, parameters);
        }
        
        private static void InitMappers()
        {
            AutoMapping.RegisterConverter<ZonedDateTime, DateTime>(zonedDateTime => zonedDateTime.ToDateTimeOffset().DateTime);
            AutoMapping.RegisterConverter<ZonedDateTime, DateTime?>(zonedDateTime => zonedDateTime.ToDateTimeOffset().DateTime);
            
            AutoMapping.RegisterConverter<TUserAuth, Dictionary<string, object>>(userAuth =>
            {
                var dictionary = userAuth.ToObjectDictionary();
                dictionary[nameof(UserAuth.Meta)] = userAuth.Meta.ToJsv();
                dictionary[nameof(UserAuth.Roles)] = userAuth.Roles.ToJsv();
                dictionary[nameof(UserAuth.Permissions)] = userAuth.Permissions.ToJsv();
                return dictionary;
            });

            AutoMapping.RegisterConverter<TUserAuthDetails, Dictionary<string, object>>(userAuthDetails =>
            {
                var dictionary = userAuthDetails.ToObjectDictionary();
                dictionary[nameof(UserAuthDetails.Items)] = userAuthDetails.Items.ToJsv();
                dictionary[nameof(UserAuthDetails.Meta)] = userAuthDetails.Meta.ToJsv();
                return dictionary;
            });
        }
        
        private static void TryConvertToInteger(string strValue, string? varName, out int result)
        {
            if (!int.TryParse(strValue, out result))
                throw new ArgumentException(@"Cannot convert to integer", varName ?? "string");
        }
    }

    internal static class DriverExtensions
    {
        public static async Task<T> ReadTxQueryAsync<T>(this IDriver driver, Func<IAsyncTransaction, Task<T>> txFn)
        {
            await using var session = driver.AsyncSession();
            var tx = await session.BeginTransactionAsync();
            var result = await txFn(tx);
            await tx.CommitAsync();
            return result;
        }

        public static async Task<IResultCursor> WriteQueryAsync(this IDriver driver, string statement, object? parameters = null)
        {
            await using var session = driver.AsyncSession();
            return await session.ExecuteWriteAsync( tx => tx.RunAsync(statement, parameters));
        }
        
        public static async Task WriteTxQueryAsync(this IDriver driver, Func<IAsyncTransaction,Task> txFn)
        {
            await using var session = driver.AsyncSession();
            var tx = await session.BeginTransactionAsync();
            await txFn(tx);
            await tx.CommitAsync();
        }
    }
    
    internal static class RecordExtensions
    {
        public static async Task<IEnumerable<TReturn>> Map<TReturn>(
            this IResultCursor records)
        {
            
            if (records.PeekAsync() == null) return new List<TReturn>();
            var listAsync = await records.ToListAsync();
            return listAsync.Select(record => record.Map<TReturn>());
        }

        public static TReturn Map<TReturn>(this IRecord record)
        {
            return ((IEntity) record[0]).Properties.FromObjectDictionary<TReturn>();
        }
    }
