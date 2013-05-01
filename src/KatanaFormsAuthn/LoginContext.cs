using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security.Forms;

namespace KatanaFormsAuthn
{
    public class LoginContext
    {
        private readonly IDictionary<string, object> _environment;
        public OwinRequest Request { get; set; }
        public OwinResponse Response { get; set; }

        private readonly FormsAuthenticationProvider _formsAuthenticationProvider;
        private readonly Stream _responseStream;
        private readonly bool _isFormUrlEncodedPost;
        private readonly NameValueCollection _formData;

        public static bool GetIsLoginRequest(IDictionary<string, object> environment)
        {
            return environment.ContainsKey("formsauthn.username")
                    && environment.ContainsKey("formsauthn.password")
                    && environment.ContainsKey("formsauthn.remember");
        }

        /// <summary>
        /// Inspects the environment and checks to see if this is a POST containing the HTML form fields in the login.html page.
        /// </summary>
        /// <param name="environment"></param>
        /// <param name="formsAuthenticationProvider"></param>
        public LoginContext(IDictionary<string, object> environment, FormsAuthenticationProvider formsAuthenticationProvider)
        {
            _environment = environment;
            Request = new OwinRequest(environment);
            Response = new OwinResponse(environment);

            _formsAuthenticationProvider = formsAuthenticationProvider;

            _responseStream = Response.Body;

            var requestContentType = Request.GetHeader("Content-Type");
            _isFormUrlEncodedPost = Request.Method == "POST" && !string.IsNullOrEmpty(requestContentType) && requestContentType.StartsWith("application/x-www-form-urlencoded");

            if (_isFormUrlEncodedPost && Request.Body != null)
            {
                _formData = Request.ReadForm().Result;

                var username = _formData["login_username"];
                var password = _formData["login_password"];
                var rememberMe = _formData["remember_me"] != null && _formData["remember_me"] == "yes";

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    environment["formsauthn.username"] = username;
                    environment["formsauthn.password"] = password;
                    environment["formsauthn.remember"] = rememberMe;
                }
            }
        }

        public Task ProcessLogin()
        {
            // I need to stuff the username nad password into the environment because 
            // FormsValidateLoginContext doesn't store the constructor parameters 
            // as properties.  Not sure if that's by design.

            var formsValidateLoginContext = new FormsValidateLoginContext(_environment, "Application", _environment["formsauthn.username"] as string, _environment["formsauthn.password"] as string);
            return _formsAuthenticationProvider.ValidateLogin(formsValidateLoginContext);
        }

        public Task ProcessNewUser()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Sorry.  We're closed.");
            var messageBytes = Encoding.UTF8.GetBytes(sb.ToString());
            return _responseStream.WriteAsync(messageBytes, 0, messageBytes.Length);
        }
    }
}