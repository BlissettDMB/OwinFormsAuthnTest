using System;
using Microsoft.Owin.Security.Forms;
using Owin;

namespace KatanaFormsAuthn
{
    public static class LoginFormExtensions
    {
        public static IAppBuilder UseProcessLoginPostback(this IAppBuilder builder, FormsAuthenticationProvider formsAuthenticationProvider)
        {
            if (builder == null)
            {
                throw new ArgumentNullException("builder");
            }
            return builder.Use(typeof(LoginFormMiddleware), formsAuthenticationProvider);
        }
    }
}