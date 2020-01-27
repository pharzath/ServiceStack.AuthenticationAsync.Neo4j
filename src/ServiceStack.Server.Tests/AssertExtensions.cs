using System;

namespace ServiceStack.Server.Tests
{
    public static class AssertExtensions
    {
        public static string ThrowIfNotConvertibleToInteger(this string strValue, string varName)
        {
            if (!int.TryParse(strValue, out _))
                throw new ArgumentException("Cannot convert to integer", varName ?? "string");

            return strValue;
        }
        
    }
}