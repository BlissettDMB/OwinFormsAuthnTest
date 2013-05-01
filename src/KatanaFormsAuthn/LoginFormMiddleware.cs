using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin.Security.Forms;

namespace KatanaFormsAuthn
{
    public class LoginFormMiddleware
    {
        private readonly Func<IDictionary<string, object>, Task> _next;
        private readonly FormsAuthenticationProvider _formsAuthenticationProvider;

        public LoginFormMiddleware(Func<IDictionary<string, object>, Task> next, FormsAuthenticationProvider formsAuthenticationProvider)
        {
            if (next == null)
            {
                throw new ArgumentNullException("next");
            }
            if (formsAuthenticationProvider == null)
            {
                throw new ArgumentNullException("formsAuthenticationProvider");
            }

            _next = next;
            _formsAuthenticationProvider = formsAuthenticationProvider;
        }

        public Task Invoke(IDictionary<string, object> environment)
        {
            var context = new LoginContext(environment, _formsAuthenticationProvider);
            if (LoginContext.GetIsLoginRequest(environment))
            {
                return context.ProcessLogin();
            }
            return _next(environment);
        }
    }
}